rule MAL_JS_Gootloader_HTML_Minifier_29Apr24 {
	meta:		
		description = "Detects Gootloader JS hidden in the HTML Minifier 4.0.0 Library"
		author = "@Gootloader"
		date = "2024-04-29"
		tlp = "CLEAR"
	strings:		
		$string1 = "HTMLMinifier v4.0.0"
		$string2 = " % ("
		
	condition:
		all of them
}