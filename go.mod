module github.com/qo-proto/wireshark-plugin

go 1.25.1

require (
	github.com/tbocek/qotp v0.2.2
	github.com/qh-project/qh v0.0.0
)

replace (
	github.com/tbocek/qotp => ./qotp
	github.com/qh-project/qh => ./qh
)
