rule MAL_JS_Gootloader17June24 {
	meta:		
		description = "Detects Gootloader JS hidden in unknown JavaScript library"
		author = "@Gootloader"
		date = "2024-06-17"
		tlp = "CLEAR"
	strings:		
		$string1 = "tf.js.map"
		$string2 = " % ("
		$string3 = "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND"
		
	condition:
		#string1 >= 1
		and #string2 >= 2
		and #string3 >= 500
		and all of them
}