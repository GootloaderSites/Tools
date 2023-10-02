rule MAL_JS_Gootloader_Sep23 {
	meta:		
		description = "Detects Gootloader JS hidden in Material Design Lite 1.3.0 Library"
		author = "@Gootloader"
		date = "2023-09-18"
		threat_names = "Gootloader"
		tlp = "CLEAR"
	strings:
		$string1 = ";(function() {"
		$string2 = "use strict"
		$string3 = "@license"
		$string4 = "Copyright 2015 Google Inc. All Rights Reserved."
		$string5 = "@author Jason Mayes."
	condition:
		uint16(0) == 0x283b
		and filesize > 100KB and filesize < 200KB 
		and $string1 at 0
		and all of them
}
