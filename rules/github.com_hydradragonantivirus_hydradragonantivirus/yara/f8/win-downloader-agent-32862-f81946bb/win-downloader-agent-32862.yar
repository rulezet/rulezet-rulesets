rule Win_Downloader_Agent_32862
{
strings:
	$a0 = { a89c3a4ff950f18dd3adec46d34981932f67858005908f2f3bb750916784dbc8170fe2d44e05dc983fb493aa6d99899897c7b89158d3a2eaf7d80dcb5e8e }


condition:
	$a0
}