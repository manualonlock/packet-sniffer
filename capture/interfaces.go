package capture

type Capturer interface {
	Capture() ([]byte, error)
}
