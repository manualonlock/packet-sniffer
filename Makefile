DLV_BIN := ~/go/bin/dlv


.PHONY: debug


debug:
	${DLV_BIN} debug


terminal:
	@sudo go run main.go -mode terminal

stdout:
	@sudo go run main.go -mode stdout