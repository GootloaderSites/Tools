rule MAL_JS_Gootloader_New_Angular_26Sep24 {
	meta:		
		description = "Detects malicious Gootloader JS hidden in the Angular 12.2.17 Library"
		author = "@Gootloader"
		date = "2024-09-25"
		tlp = "CLEAR"
	strings:		
		$string1 = "license Angular v12.2.17"
		$string2 = " % ("
		
	condition:
		#string1 >= 1
		and #string2 >= 1
		and all of them
}