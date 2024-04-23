rule MAL_JS_Gootloader_eChart_23Apr24 {
	meta:		
		description = "Detects Gootloader JS hidden in the eChart Library"
		author = "@Gootloader"
		date = "2024-04-23"
		tlp = "CLEAR"
	strings:		
		$string1 = "N0500LLLLLLLLLL00NNNLzWW"
		$string2 = " % ("
		
	condition:
		#string1 >= 2
		and #string2 >= 3
		and all of them
}