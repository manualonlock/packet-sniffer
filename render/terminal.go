package render

import (
	"errors"
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"log"
	units "packet_sniffer/model"
	"strconv"
	"time"
)

var columns = []string{"#", "Time:", "Source:", "Destination:", "Protocol:", "Size:"}

func Table() *tview.Table {
	table := tview.NewTable()
	table.SetFixed(1, 1)
	table.SetBorders(false).SetBorder(true).SetBorderColor(tcell.ColorLightSeaGreen)
	table.SetTitle("Network interface: wlp0s20f3").SetTitleColor(tcell.ColorLightSeaGreen)
	table.SetSelectable(true, false)
	return table
}

func PDUDetailedViewBox() *tview.Table {
	table := tview.NewTable()
	table.SetSelectable(true, false)
	table.SetBorderColor(tcell.ColorMediumPurple)
	table.SetBorder(true)
	return table
}

func PDUBreakDownBox() *tview.Table {
	table := tview.NewTable()
	table.SetSelectable(false, false)
	table.SetBorderColor(tcell.ColorLightYellow)
	table.SetBorder(true)
	return table
}

type TerminalRenderer struct {
	app                *tview.Application
	table              *tview.Table
	PDUBreakDownBox    *tview.Table
	pduDetailedViewBox *tview.Table

	pduCache             *map[int]*units.PDU
	pduDetailedViewCache *map[int]*units.PDU
}

func (tr *TerminalRenderer) addEtherPDU(pdu *units.PDU) error {
	destMac, _ := pdu.Headers["destMac"]
	srcMac, _ := pdu.Headers["srcMac"]

	values := []string{
		strconv.FormatInt(int64(tr.table.GetRowCount()), 10),
		time.Now().Format("2006-01-02 15:04:05"),
		destMac.HumanReadableValue,
		srcMac.HumanReadableValue,
		"Ethernet",
		strconv.FormatInt(int64(len(pdu.Payload)), 10),
	}
	go tr.app.QueueUpdateDraw(func() { tr.addRow(values) })
	return nil
}

func (tr *TerminalRenderer) addIPv4PDU(pdu *units.PDU) error {
	destIP, _ := pdu.Headers["sourceIP"]
	srcIP, _ := pdu.Headers["destIP"]

	values := []string{
		strconv.FormatInt(int64(tr.table.GetRowCount()), 10),
		time.Now().Format("2006-01-02 15:04:05"),
		destIP.HumanReadableValue,
		srcIP.HumanReadableValue,
		units.ProtocolStringMap[pdu.Protocol],
		strconv.FormatInt(int64(len(pdu.Payload)), 10),
	}
	go tr.app.QueueUpdateDraw(func() { tr.addRow(values) })
	return nil
}
func (tr *TerminalRenderer) AddPDU(pdu *units.PDU) error {
	pduCache := *tr.pduCache
	outerPDU := pdu

	for outerPDU.NextPDU != nil {
		outerPDU = outerPDU.NextPDU
	}
	pduCache[tr.table.GetRowCount()+1] = pdu
	switch outerPDU.Protocol {
	case units.ETHERNET:
		return tr.addEtherPDU(outerPDU)
	case units.IPv4:
		return tr.addIPv4PDU(outerPDU)
	}
	return nil
}

func (tr *TerminalRenderer) addRow(values []string) error {
	if len(values) != len(columns) {
		return errors.New("columns and values are not of equal length")
	}
	rowCount := tr.table.GetRowCount()
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
		tr.table.SetCell(rowCount, i, cell)
	}
	return nil
}

func (tr *TerminalRenderer) DetailedViewDisplayPDU(pdu *units.PDU) {
	outerPDU := pdu
	rowCount := 0
	tr.pduDetailedViewBox.Clear()
	pduDetailedViewCache := *tr.pduDetailedViewCache
	for h := range pduDetailedViewCache {
		delete(pduDetailedViewCache, h)
	}
	for outerPDU != nil {
		var cell *tview.TableCell
		switch outerPDU.Protocol {
		case units.ETHERNET:
			cell = tview.NewTableCell(fmt.Sprintf("Ethernet, Src: %s, Dst: %s", outerPDU.Headers["srcMac"].HumanReadableValue, outerPDU.Headers["destMac"].HumanReadableValue))
		case units.IPv4:
			cell = tview.NewTableCell(fmt.Sprintf("Internet Protocol V4, Src: %s, Dst: %s", outerPDU.Headers["sourceIP"].HumanReadableValue, outerPDU.Headers["destIP"].HumanReadableValue))
		}

		pduDetailedViewCache[rowCount] = outerPDU
		cell.SetExpansion(1)
		tr.pduDetailedViewBox.SetCell(rowCount, 0, cell)
		outerPDU = outerPDU.NextPDU
		rowCount++
	}
}

func (tr *TerminalRenderer) BreakDownTableDisplayPDU(row, column int) {
	if row > tr.PDUBreakDownBox.GetRowCount() {
		return
	}
	pduDetailedViewCache := *tr.pduDetailedViewCache
	tr.PDUBreakDownBox.Clear()
	pdu := pduDetailedViewCache[row]

	switch pdu.Protocol {
	case units.ETHERNET:
		tr.PDUBreakDownBox.SetCell(0, 0, tview.NewTableCell("Destination:"))
		tr.PDUBreakDownBox.SetCell(0, 1, tview.NewTableCell(pdu.Headers["destMac"].HumanReadableValue))
		tr.PDUBreakDownBox.SetCell(1, 0, tview.NewTableCell("Source:"))
		tr.PDUBreakDownBox.SetCell(1, 1, tview.NewTableCell(pdu.Headers["srcMac"].HumanReadableValue))
	case units.IPv4:
		tr.PDUBreakDownBox.SetCell(0, 0, tview.NewTableCell("Version:"))
		tr.PDUBreakDownBox.SetCell(0, 1, tview.NewTableCell(pdu.Headers["version"].HumanReadableValue))
		tr.PDUBreakDownBox.SetCell(1, 0, tview.NewTableCell("IHL:"))
		tr.PDUBreakDownBox.SetCell(1, 1, tview.NewTableCell(pdu.Headers["headerLength"].HumanReadableValue))
	}
}

func (tr *TerminalRenderer) tableSelectionChange(row, column int) {
	pduCache := *tr.pduCache
	tr.DetailedViewDisplayPDU(pduCache[row])
}

func (tr *TerminalRenderer) Init() {
	tr.app = tview.NewApplication()
	tr.app.EnableMouse(true)
	tr.table = Table()
	tr.table.SetSelectionChangedFunc(tr.tableSelectionChange)
	pduCache := make(map[int]*units.PDU, 10)
	tr.pduCache = &pduCache

	tr.pduDetailedViewBox = PDUDetailedViewBox()
	pduDetailedViewCache := make(map[int]*units.PDU, 10)
	tr.pduDetailedViewCache = &pduDetailedViewCache
	tr.pduDetailedViewBox.SetSelectionChangedFunc(tr.BreakDownTableDisplayPDU)
	tr.PDUBreakDownBox = PDUBreakDownBox()
	rootFlexBox := tview.NewFlex()
	rootFlexBox.AddItem(tr.table, 0, 6, false)

	rightFlex := tview.NewFlex().SetDirection(tview.FlexRow)
	rightFlex.AddItem(tr.pduDetailedViewBox, 0, 1, false)
	rightFlex.AddItem(tr.PDUBreakDownBox, 0, 1, false)

	rootFlexBox.AddItem(rightFlex, 0, 4, false)

	go tr.app.QueueUpdateDraw(func() { tr.addRow(columns) })
	tr.app.SetRoot(rootFlexBox, true)
}

func (tr *TerminalRenderer) Run() {
	log.Fatal(tr.app.Run())
}
