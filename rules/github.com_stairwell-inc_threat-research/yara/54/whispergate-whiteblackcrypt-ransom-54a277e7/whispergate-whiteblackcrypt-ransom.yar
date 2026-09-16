rule WhisperGate_WhiteBlackCrypt_ransom
{
    meta:
        author= "Silas Cutler (silas@Stairwell.com)"
        description = "Matches ransom note seen in WhiteBlackCrypt"
        ref = "https://cip.gov.ua/ua/news/informaciya-shodo-imovirnoyi-provokaciyi"
        version = "0.1"
    strings:
		$ = "Your files has been ENCRYPTED! Now, you cant access them, but they are not deleted. We need to get 10 BTC at the specified address:"
		$ = "19B5Bt11oUqYnwSXfBgRpwwDGg5Ajirbjn"
		$ = "we will send text document to you mail with a PRIVATE RSA key, and a link to a program, that can decrypt"
		$ = "all files on every computer, encrypted with this program"
		$ = "If we recieve moneys, "
		$ = "for acquiring decryption key, please send us"
		$ = "address of your bitcoin wallet."
    condition:
        3 of them    
}