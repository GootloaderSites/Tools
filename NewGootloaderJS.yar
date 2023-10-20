rule MAL_JS_Gootloader_Oct23 {
	meta:		
		description = "Detects Gootloader JS hidden in Google Closure Library"
		author = "@Gootloader"
		date = "2023-10-20"
		threat_names = "Gootloader"
		tlp = "CLEAR"
	strings:		
		$string1 = "var goog = goog || {};"
		$string2 = "Builds an object structure for the provided namespace path"
		$string3 = "Copyright The Closure Library Authors"
		$string4 = " % ("
		$string5 = ")] = "
	condition:
		filesize > 100KB and filesize < 200KB 
		and all of them
}
