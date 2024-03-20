rule MAL_JS_Gootloader_eChart_20Mar24 {
	meta:		
		description = "Detects Gootloader JS hidden in the eChart Library"
		author = "@Gootloader"
		date = "2024-03-20"
		tlp = "CLEAR"
	strings:		
		$string1 = "N0500LLLLLLLLLL00NNNLzWW"
		$string2 = " % ("
		
	condition:
		filesize > 20000KB and filesize < 25000KB
		and #string1 == 7
		and #string2 == 21
		and all of them
}