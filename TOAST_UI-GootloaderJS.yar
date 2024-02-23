rule MAL_JS_Gootloader_TOAST_UI_23Feb24 {
	meta:		
		description = "Detects Gootloader JS hidden in the TOAST UI Library"
		author = "@Gootloader"
		date = "2024-02-23"
		tlp = "CLEAR"
	strings:		
		$string1 = "Fri Jan 29 2021 15:51:40 GMT+0900 (Korean Standard Time)"
		$string2 = " % ("
		
	condition:
		filesize > 1700KB and filesize < 1800KB
		and #string2 == 3
		and all of them
}
