.PHONY: test-cover clean-cover patch minor major

test-cover:
	go test -coverprofile=cover.out ./ 
	go tool cover -html=cover.out -o cover.html 

clean-cover:
	rm -f cover.out cover.html

patch:
	@bash scripts/tag.sh patch

minor:
	@bash scripts/tag.sh minor

major:
	@bash scripts/tag.sh major
