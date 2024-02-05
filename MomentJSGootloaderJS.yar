rule MAL_JS_Gootloader_Feb24 {
	meta:		
		description = "Detects Gootloader JS hidden in the MomentJS/webpack Library"
		author = "@Gootloader"
		date = "2024-02-05"
		tlp = "CLEAR"
	strings:		
		$string1 = "hooks.version = '2.18.1';"
		$string2 = "var VERSION = '4.17.4';"
		$string3 = "version : 2.18.1"
		$string4 = "var VERSION = '3.10.1';"
        $string5 = "'version': '1.1.1',"
        $string6 = "3.5.17"
		$string7 = " % ("
		
	condition:
		filesize > 3500KB and filesize < 4000KB
		and #string7 == 2
		and all of them
}
