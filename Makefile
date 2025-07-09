
test-cover:
	go test -coverprofile=cover.out ./ 
	go tool cover -html=cover.out -o cover.html 

clean-cover:
	rm -f cover.out cover.html
