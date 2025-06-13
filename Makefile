compile:
	mkdir -p Output
	cd main && pdflatex -output-directory=../Output SoftEther_VPN_Lab.tex
	cd main && pdflatex -output-directory=../Output SoftEther_VPN_Lab.tex
	mv Output/SoftEther_VPN_Lab.pdf ./

clean:
	rm -rf Output
	rm -f *.pdf

full: clean compile

.PHONY: compile clean full
