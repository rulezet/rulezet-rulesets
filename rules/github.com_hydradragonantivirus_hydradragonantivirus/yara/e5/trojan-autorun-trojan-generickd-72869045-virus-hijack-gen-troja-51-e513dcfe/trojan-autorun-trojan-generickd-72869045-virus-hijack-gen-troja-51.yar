rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_51 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@aq5b2kh_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_16_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_17_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g4X@aSzGK!f_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash3       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash4       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash5       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash6       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash7       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash8       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash9       = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"
    hash10      = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash11      = "9b1f053694c3db989f5c342cf8e2239bee4a1942950b85043637104969e007fe"
    hash12      = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash13      = "322b1709b0a1998c1bcc8d7ecf62946f9bc72e205ae3f51181890f71efcba474"
    hash14      = "d77b112f1683e3c12780036badc6740837837590150bd82023b8f87eb19ac119"
    hash15      = "b191c91e710f1e6d5bba7192208e4582b57d6ca6ab1478dbb8b815207d74aa5f"
    hash16      = "819bdd89651a57972b9b57227d3b6bd3d94ff991732ba0b0e8459b9fb607a9f4"
    hash17      = "6300694b02f0d03c3a18fe78114e8ee3bb4ccb33360a8beef079c18ca3bc5e8a"
    hash18      = "97bc5369195339aa2c26e05972ac2b0e937dbc52dd3a05bc4f29533ffc3d7dbd"
    hash19      = "7a123956fa172c66ed84236a35e0b1f3587bf3d190c604be3c7399fca5ba4571"

  strings:
    $s1  = "  CSL is an open standard to define styles. The styles are processed using <a href=\"https://github.com/Juris-M/citeproc-js\">ci" ascii
    $s2  = "  CSL is an open standard to define styles. The styles are processed using <a href=\"https://github.com/Juris-M/citeproc-js\">ci" ascii
    $s3  = " 2008 Glyph &amp; Cog, LLC. Fugue Icons by <a href=\"http://p.yusukekamiyamane.com/\">Pinvoke</a>. Reference styles are formatte" ascii
    $s4  = "Tip: Use <a href=\"http://support.mendeley.com/customer/portal/articles/227955\">search modifiers</a> to narrow your results." fullword ascii
    $s5  = " 2008 Glyph &amp; Cog, LLC. Fugue Icons by <a href=\"http://p.yusukekamiyamane.com/\">Pinvoke</a>. Reference styles are formatte" ascii
    $s6  = "  All styles are offered under the <a href=\"http://creativecommons.org/licenses/by-sa/3.0/\">Creative Commons Attribution-Share" ascii
    $s7  = "  All styles are offered under the <a href=\"http://creativecommons.org/licenses/by-sa/3.0/\">Creative Commons Attribution-Share" ascii
    $s8  = "There was a problem opening your database. A temporary database was created instead. Please note that <b>changes will not be sav" ascii
    $s9  = "  Mendeley regularly fetches new styles from Citation Styles project <a href=\"https://github.com/citation-style-language/styles" ascii
    $s10 = "Please see the Mendeley <a href=\"https://www.elsevier.com/legal/privacy-policy\" >Privacy Policy</a> for more details on how Me" ascii
    $s11 = "Please see the Mendeley <a href=\"https://www.elsevier.com/legal/privacy-policy\" >Privacy Policy</a> for more details on how Me" ascii
    $s12 = "using <a href=\"https://citationstyles.org\">Citation Style Language</a> and <a href=\"https://github.com/Juris-M/citeproc-js\">" ascii
    $s13 = "class QExplicitlySharedDataPointer<class ExportJob> __thiscall ImportExportDialogProvider::showExportDialog(class QWidget *,cons" ascii
    $s14 = "bool __thiscall AnnotationsExportSettingsDialog::exportPDFWithNotes(const class DocumentFile &,class QTreeWidgetItem *,const cla" ascii
    $s15 = "class QExplicitlySharedDataPointer<class ExportJob> __thiscall ImportExportDialogProvider::showExportDialog(class QWidget *,cons" ascii
    $s16 = "proc-js</a>. Note background image taken from the <a href=\"https://plasma.kde.org\">Plasma</a> project. PDF technology in Mende" ascii
    $s17 = "<a href='https://%1/forgot/'>Forgot password?</a>" fullword ascii
    $s18 = "LaTeX Citation Command" fullword ascii
    $s19 = "Mendeley Desktop will forget when it last synced with your online account and refetch all data on the next sync. Continue?" fullword ascii
    $s20 = "/* dark  grey #787878 */" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}