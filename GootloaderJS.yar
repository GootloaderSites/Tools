rule Gootloader_js {
	meta:		
		TLP = "CLEAR"
		description = "Detects Gootloader JS hidden in Material Design Lite 1.1.2 Library"
		author = "@Gootloader"
		date = "2023-09-13"
		threat_names = "Gootloader"
	strings:
		$js_pattern = /[a-z0-9]{1,}\([0-9]{1,5}\);/
		$string1 = ";(function() {"
		$string2 = "use strict"
		$string3 = "@license"
		$string4 = "Copyright 2015 Google Inc. All Rights Reserved."
		$string5 = "@author Jason Mayes."
	condition:
		all of them and filesize > 100KB and filesize < 200KB
}