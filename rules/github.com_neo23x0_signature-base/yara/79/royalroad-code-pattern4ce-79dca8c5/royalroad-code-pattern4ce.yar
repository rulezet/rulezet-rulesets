rule RoyalRoad_code_pattern4ce
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "nao_sec"
      score = 80
      id = "c6e8a072-23cd-5f6a-9b4f-57d3e4500d13"
    strings:
        $S1= "584242eb064242423535333620446060606060606060606161616161616161616161616}1616161" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1
}