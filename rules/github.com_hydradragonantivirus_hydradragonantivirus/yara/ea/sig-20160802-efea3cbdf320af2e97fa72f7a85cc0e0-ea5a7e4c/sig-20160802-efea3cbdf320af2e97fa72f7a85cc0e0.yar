rule sig_20160802_efea3cbdf320af2e97fa72f7a85cc0e0 {
  meta:
    description = "datamaliciousorder - file 20160802_efea3cbdf320af2e97fa72f7a85cc0e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8b539ef8241f9bded43964aeeddb24aef442b7ff73dec0e2a70735d5d7b9a55"

  strings:
    $s1  = "    var aWPi3 = 'if (WScript.Path[\\x22cha\\x72At\\x22](\\x57Script.\\x50ath.\\x6cength-1) \\x21=\\x20\"2\") WSc\\x72ipt.\\x51" ascii
    $s2  = "ript[UI\\x6d + Yj(Sh)\\x5d(1000)\\x3b continue\\x3b\\x7d;\\r\\n} while \\x28Uz);\\r\\n\\r\\nWScript.Quit(0);\\r\\x0a\\r\\x0a\\x6" ascii
    $s3  = "IJh\\x28){return Ca;}())+Hg+FEe\\x5d;\\r\\nvar Ba5=WScript[Eq8 + KEy7 + Jy7 + LXw](Me + Yz4\\x20+\\x20Kr6\\x20+ Bz\\x29;\\r\\nva" ascii
    $s4  = "-= n;\\r\\nn += h\\x20* 0x100000000;\\r\\n}\\r\\nreturn (n >>> 0) *\\x202.328\\x330643653\\x386963\\x65-\\x310;\\r\\n} else n = " ascii
    $s5  = " O\\x50j=693\\x38 -\\x20\\x36938; O\\x50j < Tf0[\\x4a\\x51u(QSc) + (function Cn2(){return OXv9;}())]; O\\x50j++)\\r\\n\\t{\\x0d" ascii
    $s6  = ";\\x0d\\nPa\\x37[253]=178;\\r\\nPa7[254]=193\\x363 - 9731;\\r\\nP\\x617[255]=160;\\r\\n\\t\\r\\n\\tvar Dq\\x3dnew Array(\\x29;" ascii
    $s7  = "\\x20Tv(){\\x72eturn KEy7\\x3b\\x7d()) + (function EHf(){retu\\x72n Jy\\x37;}()) +\\x20LXw](GJu+OIo+FDz2(VTk0)+Ih2 + GTg \\x2b X" ascii
    $s8  = "x53cr\\x69pt[(\\x66unction SWb(){return Eq8;}()) + KEy7 + BZb(J\\x797) + PM\\x712(L\\x58w\\x29]\\x28GJu+OIo+STv\\x30(VTk0)+Ih\\x" ascii
    $s9  = "d\\nfunction VOy7(DHf1\\x20/* y\\x20 */)\\r\\n{\\r\\n\\x09if (DHf1[\\x30\\x5d==\\x200x4D && DH\\x661[1]== \\x30x5a)\\r\\n\\t\\t{" ascii
    $s10 = "return Y\\x53a;};funct\\x69o\\x6e PMq2(Qx){ret\\x75rn Qx;};var\\x20LXw = \"t\" + \"\";\\r\\nvar Jy\\x37 = \"jec\" + \"\";\\r\\nv" ascii
    $s11 = "\\n\\t\\t\\t{\\r\\n\\t\\t\\t\\t\\x4fEq\\x36\\x3d0;\\r\\n\\t\\t\\x09\\tW\\x53cri\\x70t[UIm + DLr5(Sh)](1000);\\r\\n\\t\\t\\t}\\x0" ascii
    $s12 = "8){return Tl8;};var Xe1 = \"h\" \\x2b \"\";\\r\\nvar Lm = \"pu\\x73\\x22\\x20+\\x20\"\";\\r\\nvar Rt\\x20= \"At\"\\x20+ \"\";\\x" ascii
    $s13 = "fun\\x63tion Su(\\x53H\\x764){return SH\\x764;};var Xt6\\x20= \"\\x6cl\" + \"\";\\r\\nva\\x72 M\\x53\\x6c = \"ll\" + \"\";\\r\\n" ascii
    $s14 = "i8;}()), Zs5 \\x2b Te1\\x20+ Su(\\x4dSl) + \\x58t6);\\r\\nvar UWy4=Pe0[Q'+''+'\\x53c + (function LBy(){return OX\\x769\\x3b}())]" ascii
    $s15 = "o\\x3dEFq7;}\\r\\n\\t\\telse\\r\\n\\t\\t\\t\\x7bvar ENo=Sq[EFq'+''+'7];}\\r\\x0a\\t\\tHFz[Mc0(Lm) + (function Eo6\\x28){re\\x74u" ascii
    $s16 = "DQb + \\x58Eh,\\x20\\x58Ru + Sp +\\x20\\x43k9(L\\x770) \\x2b Br5];\\r\\n\\r\\n\\x66or \\x28var OPj=0; OPj < P\\x65[QSc + (functi" ascii
    $s17 = "x58h1){return X\\x68\\x31;};var Lr8 \\x3d \"noa\\x72r\" \\x2b \"\";\\r\\x0avar QRy5 = \"nti\\x22 + \\x22\";\\r\\nvar M\\x53c5 = " ascii
    $s18 = "70en\" + \"\";\\r\\nfunction DLr5(Bx7){ret\\x75rn B\\x787;};function Y\\x6a\\x28Kf1){\\x72e\\x74urn K\\x661;};var Sh = \"p\" + " ascii
    $s19 = "Gs4 + Pa1\\x29;\\x0d\\nvar\\x20Gz = 672168;\\r\\nvar Id=NVd[QSc\\x20+ OXv9];\\r\\nvar Pe0=(Dv\\x33\\x20\\x2b KJd + (function IMn" ascii
    $s20 = "00;\\r\\n\\t};\\r\\n\\tif \\x28RE\\x74\\x32\\x20!= C\\x6d) {return \\x5b];};\\r\\n\\t\\r\\n\\tretur\\x6e\\x20DHf1 /* y\\x20 */" ascii

  condition:
    uint16(0) == 0x200a and
    8 of them
}