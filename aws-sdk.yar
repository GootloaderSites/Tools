rule MAL_JS_Gootloader_AWS_SDK_22Jul24 {
	meta:		
		description = "Detects malicious Gootloader JS hidden in the AWS SDK JavaScript v2.1560.0 Library"
		author = "@Gootloader"
		date = "2024-07-22"
		tlp = "CLEAR"
	strings:		
		$string1 = "AWS SDK for JavaScript v2.1560.0"
		$string2 = " % ("
		
	condition:
		all of them
}