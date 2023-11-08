rule MAL_JS_Gootloader_Nov23 {
	meta:		
		description = "Detects Gootloader JS hidden in the SheetJS Library"
		author = "@Gootloader"
		date = "2023-11-08"
		threat_names = "Gootloader"
		tlp = "CLEAR"
	strings:		
		$string1 = "xlsx.js (C) 2013-present SheetJS"
		$string2 = "shim.js (C) 2013-present SheetJS"
		$string3 = "0.18.5"
		$string4 = " % ("
		
	condition:
		filesize > 750KB and filesize < 950KB 
		and all of them
}