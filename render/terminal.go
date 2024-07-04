package render

import (
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	units "packet_sniffer/model"
	"packet_sniffer/parsing"
	"strconv"
	"strings"
	"time"
)

var packetListColumns = []string{"#", "Time:", "Source:", "Destination:", "Protocol:", "Size:"}

type PacketListPane struct {
	Application *tview.Application
	table       *tview.Table
	rowToPDU    *map[int]*units.PDU
	PDUHandover func(pdu *units.PDU)
}

func (p *PacketListPane) Primitive() *tview.Table {
	return p.table
}

func (p *PacketListPane) Init(iface string) {
	rowToPDU := make(map[int]*units.PDU, 1000)
	p.rowToPDU = &rowToPDU

	p.table = tview.NewTable()
	p.table.SetFixed(1, 1)
	p.table.SetBorders(false).SetBorder(true).SetBorderColor(tcell.ColorLightSeaGreen)
	p.table.SetTitle(fmt.Sprintf("Network interface: %s", iface)).SetTitleColor(tcell.ColorLightSeaGreen)
	p.table.SetSelectable(true, false)

	p.table.SetSelectionChangedFunc(func(row, column int) {
		pdu := rowToPDU[row]
		p.PDUHandover(pdu)
	})

	go p.Application.QueueUpdateDraw(func() { p.AddRow(packetListColumns...) })

}

func (p *PacketListPane) AddPDU(pdu *units.PDU) {
	var source string
	var dest string
	var protocol string
	var length string

	currentPDU := pdu
	for currentPDU != nil {
		if currentPDU.NextPDU == nil {
			protocol = units.ProtocolStringMap[currentPDU.Protocol].Shortened
			length = strconv.FormatInt(int64(len(currentPDU.Payload)), 10)
		}
		parser := parsing.ParserFromProtocol(currentPDU.Protocol)

		srcHeader, hit := currentPDU.Headers[parsing.SRCHeader]
		if hit == true {
			source = parser.HeaderToHumanReadable(parsing.SRCHeader, srcHeader)
		}
		dstHeader, hit := currentPDU.Headers[parsing.DSTHeader]
		if hit == true {
			dest = parser.HeaderToHumanReadable(parsing.DSTHeader, dstHeader)
		}
		currentPDU = currentPDU.NextPDU
	}
	go p.Application.QueueUpdateDraw(func() { p.AddRow(source, dest, protocol, length) })
	rowToPDU := *p.rowToPDU
	rowToPDU[p.table.GetRowCount()] = pdu
}

func (p *PacketListPane) AddRow(initialValues ...string) error {
	rowCount := p.table.GetRowCount()
	var values []string
	if rowCount == 0 {
		values = initialValues
	} else {
		values = append([]string{strconv.FormatInt(int64(p.table.GetRowCount()), 10), time.Now().Format("2006-01-02 15:04:05")}, initialValues...)
	}

	for i, v := range values {
		var color tcell.Color
		if rowCount == 0 {
			color = tcell.ColorYellow
		} else {
			color = tcell.ColorWhite
		}
		cell := tview.NewTableCell(v)
		if rowCount == 0 {
			cell.SetSelectable(false)
		} else {
			if i == 4 {
				color = tcell.ColorLightGreen
			}
		}
		cell.SetAlign(tview.AlignLeft)
		if i == len(values)-1 {
			cell.SetExpansion(1)
		}
		cell.SetTextColor(color)
		p.table.SetCell(rowCount, i, cell)
	}
	return nil
}

type PacketDetailsPane struct {
	Application *tview.Application
	table       *tview.Table
	rowToPDU    *map[int]*units.PDU
	PDUHandover func(pdu *units.PDU)
}

func (p *PacketDetailsPane) Primitive() *tview.Table {
	return p.table
}

func (p *PacketDetailsPane) Init() {
	rowToPDU := make(map[int]*units.PDU, 10)
	p.rowToPDU = &rowToPDU

	p.table = tview.NewTable()
	p.table.SetSelectable(true, false)
	p.table.SetBorderColor(tcell.ColorMediumPurple)
	p.table.SetBorder(true)

	p.table.SetSelectionChangedFunc(func(row, column int) {
		pdu := rowToPDU[row]
		p.PDUHandover(pdu)
	})

}

func (p *PacketDetailsPane) AddPDU(pdu *units.PDU) {
	p.table.Clear()
	currentPDU := pdu
	for currentPDU != nil {
		rowToPDU := *p.rowToPDU
		rowToPDU[p.table.GetRowCount()] = currentPDU

		parser := parsing.ParserFromProtocol(currentPDU.Protocol)

		msh := parser.MostSignificantHeaders()
		values := make([]string, len(msh)+1)
		values[0] = units.ProtocolStringMap[currentPDU.Protocol].Full

		for i := 0; i < len(msh); i++ {
			hhr := parser.HeaderToHumanReadable(msh[i], currentPDU.Headers[msh[i]])
			values[i+1] = fmt.Sprintf("%s: %s", parser.HeaderName(msh[i]), hhr)
		}
		p.AddRow(strings.Join(values, ", "))
		currentPDU = currentPDU.NextPDU
	}
}

func (p *PacketDetailsPane) AddRow(value string) {
	cell := tview.NewTableCell(value)
	cell.SetExpansion(1)
	p.table.SetCell(p.table.GetRowCount(), 0, cell)
}

type BreakDownPane struct {
	Application *tview.Application
	table       *tview.Table
	rowToPDU    *map[int]*units.PDU
}

func (p *BreakDownPane) Primitive() *tview.Table {
	return p.table
}

func (p *BreakDownPane) addPDUBreakdownOutput(output parsing.PDUBreakdownOutput, inner bool) {
	var extra string = ""
	if inner == true {
		extra = "  -  "
	}
	if output.Description == nil {
		p.AddRow(fmt.Sprintf("%s%s: %s", extra, output.KeyName, output.Value))
	} else {
		p.AddRow(fmt.Sprintf("%s%s: %s (%s)", extra, output.KeyName, output.Value, *output.Description))
	}
}

func (p *BreakDownPane) AddPDU(pdu *units.PDU) {
	p.table.Clear()
	parser := parsing.ParserFromProtocol(pdu.Protocol)
	for _, output := range parser.PDUBreakdown(pdu) {
		p.addPDUBreakdownOutput(output, false)
		for _, o := range output.InnerBreakdowns {
			p.addPDUBreakdownOutput(o, true)
		}
	}
}

func (p *BreakDownPane) AddRow(value string) {
	cell := tview.NewTableCell(value)
	cell.SetExpansion(1)
	p.table.SetCell(p.table.GetRowCount(), 0, cell)
}

func (p *BreakDownPane) Init() {
	rowToPDU := make(map[int]*units.PDU, 10)
	p.rowToPDU = &rowToPDU

	p.table = tview.NewTable()
	p.table.SetSelectable(false, false)
	p.table.SetBorderColor(tcell.ColorLightYellow)
	p.table.SetBorder(true)
}

type Terminal struct {
	NetworkInterface  chan string
	app               *tview.Application
	packetListPane    *PacketListPane
	packetDetailsPane *PacketDetailsPane
	breakDownPane     *BreakDownPane
}

func (t *Terminal) InitPanes(iface string) {
	breakDownPane := BreakDownPane{Application: t.app}
	breakDownPane.Init()
	t.breakDownPane = &breakDownPane

	packetDetailsPane := PacketDetailsPane{Application: t.app, PDUHandover: breakDownPane.AddPDU}
	packetDetailsPane.Init()
	t.packetDetailsPane = &packetDetailsPane

	packetListPane := PacketListPane{Application: t.app, PDUHandover: packetDetailsPane.AddPDU}
	packetListPane.Init(iface)
	t.packetListPane = &packetListPane

	rootFlexBox := tview.NewFlex()
	rootFlexBox.AddItem(packetListPane.Primitive(), 0, 6, true)

	rightFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	rightFlex.AddItem(packetDetailsPane.Primitive(), 0, 1, false)
	rightFlex.AddItem(breakDownPane.Primitive(), 0, 1, false)

	rootFlexBox.AddItem(rightFlex, 0, 4, false)
	t.app.SetRoot(rootFlexBox, true)
}

func (t *Terminal) Init() {
	t.app = tview.NewApplication()
	t.app.EnableMouse(true)
}

func (t *Terminal) Start(ifaces []string) {
	if t.app == nil {
		t.Init()
	}
	modal := tview.NewModal().
		SetText("Select a network interface").AddButtons(ifaces).SetDoneFunc(
		func(buttonIndex int, buttonLabel string) {
			t.InitPanes(buttonLabel)
			t.NetworkInterface <- buttonLabel
		})
	if err := t.app.SetRoot(modal, false).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

func (t *Terminal) AddPDU(pdu *units.PDU) error {
	t.packetListPane.AddPDU(pdu)
	return nil
}
