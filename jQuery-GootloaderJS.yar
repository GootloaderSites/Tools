rule MAL_JS_Gootloader_jQuery_Compact_06Nov24 {
	meta:		
		description = "Detects malicious Gootloader JS hidden in the Query Compat JavaScript Library v3.0.0-alpha1"
		author = "@Gootloader"
		date = "2024-11-06"
		tlp = "CLEAR"
	strings:		
		$string1 = "jQuery Compat JavaScript Library v3.0.0-alpha1"
		$string2 = " % ("
		
	condition:
		#string1 >= 1
		and #string2 >= 1
		and all of them
}
