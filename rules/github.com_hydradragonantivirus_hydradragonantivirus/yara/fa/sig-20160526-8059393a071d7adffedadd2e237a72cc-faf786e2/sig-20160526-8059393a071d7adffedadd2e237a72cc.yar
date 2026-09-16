rule sig_20160526_8059393a071d7adffedadd2e237a72cc {
  meta:
    description = "datamaliciousorder - file 20160526_8059393a071d7adffedadd2e237a72cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "def90bdb4e18ffe41e82bf8cb79c9787929a2c53f17e916db8bceefc5cd32aa3"

  strings:
    $s1  = "function MvWdORFGV(NUsLcwLPjeUTA) {var PNLsorVBfDMudNP = oQxmXkVUsUNyuUdaXcLIm.join(oaeUGgkxkgWxRWAHTbQ[0]);var UQtkAajGjEYrwcxn" ascii
    $s2  = "s(57), 2) - 1))-693)) ECjdQWVEikmZJlQe += lzDvAwnnQwaJG(UQtkAajGjEYrwcxnl, RwuawjAfMJVVQWMwGawZI);else ECjdQWVEikmZJlQe += uoTIC" ascii
    $s3  = ")) ECjdQWVEikmZJlQe += Kz(UQtkAajGjEYrwcxnl);else if (hKDxTmE == (757 + Math.round((Math.pow(Math.sin(57), 2) + Math.pow(Math.co" ascii
    $s4  = "function lZcdDQVblWZTl(NVMkjHEbLGTPflChINeaYvil,cVCFmjLJbx){return NVMkjHEbLGTPflChINeaYvil.charAt(cVCFmjLJbx);}" fullword ascii
    $s5  = "function MvWdORFGV(NUsLcwLPjeUTA) {var PNLsorVBfDMudNP = oQxmXkVUsUNyuUdaXcLIm.join(oaeUGgkxkgWxRWAHTbQ[0]);var UQtkAajGjEYrwcxn" ascii
    $s6  = "function lzDvAwnnQwaJG(YrHWhCkiEATUioxSaAhEbKXd,krAXWxqYqgqzTmw){return String.fromCharCode(YrHWhCkiEATUioxSaAhEbKXd,krAXWxqYqgq" ascii
    $s7  = "function Kz(loWbmNCqnWMuoAngmsbqRaS){return String.fromCharCode(loWbmNCqnWMuoAngmsbqRaS);}" fullword ascii
    $s8  = "YNpEkKnsUfGrTllkEN(UQtkAajGjEYrwcxnl, RwuawjAfMJVVQWMwGawZI, zsapPctidBm);} while (WkalxssDfZWIHOf < NUsLcwLPjeUTA.length);retur" ascii
    $s9  = "function JTqKSwcscF(uVvjCgzu,QJKucTv){return uVvjCgzu.indexOf(QJKucTv);}" fullword ascii
    $s10 = "function lzDvAwnnQwaJG(YrHWhCkiEATUioxSaAhEbKXd,krAXWxqYqgqzTmw){return String.fromCharCode(YrHWhCkiEATUioxSaAhEbKXd,krAXWxqYqgq" ascii
    $s11 = "function uoTICYNpEkKnsUfGrTllkEN(XKGKHIJUKBjdYsCV,MrozvwHoSc,AizHCjbyXCEVCaXZxr){return String.fromCharCode(XKGKHIJUKBjdYsCV,Mro" ascii
    $s12 = "function uoTICYNpEkKnsUfGrTllkEN(XKGKHIJUKBjdYsCV,MrozvwHoSc,AizHCjbyXCEVCaXZxr){return String.fromCharCode(XKGKHIJUKBjdYsCV,Mro" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}