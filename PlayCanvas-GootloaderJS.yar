rule MAL_JS_Gootloader_PlayCanvas_16JAug24 {
	meta:		
		description = "Detects malicious Gootloader JS hidden in the PlayCanvas Engine v1.68.2 Library"
		author = "@Gootloader"
		date = "2024-08-16"
		tlp = "CLEAR"
	strings:		
		$string1 = "PlayCanvas Engine v1.68.2 revision 581ec4b (RELEASE)"
		$string2 = " % ("
		
	condition:
		#string1 >= 1
		and #string2 > 2
		and all of them
}