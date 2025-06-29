compile:
	mkdir -p Output
	cd main && pdflatex -output-directory=../Output SoftEther_VPN_Lab.tex
	cp main/references.bib Output/
	cd Output && bibtex SoftEther_VPN_Lab
	cd main && pdflatex -output-directory=../Output SoftEther_VPN_Lab.tex
	cd main && pdflatex -output-directory=../Output SoftEther_VPN_Lab.tex
	mv Output/SoftEther_VPN_Lab.pdf ./
	mv SoftEther_VPN_Lab.pdf SoftEther_VPN_Lab_Activity.pdf

clean:
	rm -rf Output
	rm -f *.pdf

full: clean compile

.PHONY: compile clean full
