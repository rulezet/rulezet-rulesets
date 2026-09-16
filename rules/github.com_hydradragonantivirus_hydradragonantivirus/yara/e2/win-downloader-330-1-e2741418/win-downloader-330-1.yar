rule Win_Downloader_330_1
{
strings:
	$a0 = { 6d3c0a4e1affce3188dfdbc7e562492eca721156953e9bc747bf82c768caaa3b03a52697dc5edec0fea4f277d79dbc99cad4297fa99a090a7e5bd0fef25cabbb6629569f895f88149d0f6ff1be6d7d1dcf9227c6 }


condition:
	$a0
}