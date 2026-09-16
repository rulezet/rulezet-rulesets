rule RoyalRoad_RTF
{
   meta:
      description = "Detects RoyalRoad weaponized RTF documents"
      reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
      date = "2020/01/15"
      author = "nao_sec"
      score = 80
      id = "366ec9c3-e6ad-5198-88d5-15aa84a8358f"
    strings:
        $S1= "objw2180\\objh300" ascii
        $RTF= "{\\rt"

    condition:
        $RTF at 0 and $S1
}