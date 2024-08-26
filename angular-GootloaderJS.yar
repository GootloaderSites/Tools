rule MAL_JS_Gootloader_Angular_26JAug24 {
	meta:		
		description = "Detects malicious Gootloader JS hidden in the AngularJS v1.8.3 Library"
		author = "@Gootloader"
		date = "2024-08-26"
		tlp = "CLEAR"
	strings:		
		$string1 = "license AngularJS v1.8.3"
		$string2 = " % ("
		
	condition:
		#string1 >= 1
		and #string2 > 2
		and all of them
}