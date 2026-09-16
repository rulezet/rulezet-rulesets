rule RoyalRoad_encode_in_RTF
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "nao_sec"
      score = 60
      id = "66614152-8f9b-5e62-b6bd-ba0286e66d4d"
    strings:
        $enc_hex_1 = "B0747746"
        $enc_hex_2 = "B2A66DFF"
        $enc_hex_3 = "F2A32072"
        $enc_hex_4 = "B2A46EFF"
        $enc_hex_1l = "b0747746"
        $enc_hex_2l = "b2a66Dff"
        $enc_hex_3l = "f2a32072"
        $enc_hex_4l = "b2a46eff"
        $RTF= "{\\rt"
    condition:
        $RTF at 0 and 1 of ($enc_hex*)
}