rule Virus_Hijack_Gen_Trojan_ShellObject_uCZ_amHJK4p_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uCZ@amHJK4p_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9112118ac9af34f65891e065c39a92afc5dd8968f1df1217f9bc1314eca4cecd"

  strings:
    $s1  = "\\System Volume Information.exe" fullword wide
    $s2  = "Black Hole.exe" fullword wide
    $s3  = "Read Me.txt" fullword wide
    $s4  = "Hi Boss, your computer has been disabled to run properly by The Black Hole. I'm sorry Boss, I will be killing your computer now." wide
    $s5  = "Zero Code.pif" fullword wide
    $s6  = "Orang yang akan selamat di alam akhirat adalah yang selamat di alam kubur." fullword wide
    $s7  = "Jangan sekali-kali berpikir untuk mengakhiri hidup dengan jalan pintas karena adanya tekanan hidup yang berat." fullword wide
    $s8  = "The ordinal %d could not be located in the DLL %s." fullword ascii
    $s9  = "The procedure %s could not be located in the DLL %s." fullword ascii
    $s10 = "Black Hole" fullword wide
    $s11 = "Control Panel\\Mouse\\" fullword wide
    $s12 = "Black Hole (Lubang Hitam)" fullword wide
    $s13 = "Bagaimana ia bisa memusnahkan benda-benda yang ada di luar angkasa?" fullword wide
    $s14 = "Dia bekerja seperti monster yang memakan apa saja yang ada di dekatnya." fullword wide
    $s15 = "Apa yang terjadi bila kita terhisap oleh Lubang Hitam?" fullword wide
    $s16 = "Yang terjadi adalah perjalanan ke antah berantah dan tidak ada jalan keluar darinya." fullword wide
    $s17 = "Apa yang ada di dalam Lubang Hitam?" fullword wide
    $s18 = "Sesuatu yang masih misterius sampai detik ini." fullword wide
    $s19 = "Adakah seorang ahli yang dapat menguaknya?" fullword wide
    $s20 = "Akankah masa depan alam semesta seperti matahari beserta planet-planetnya dan galaksi berakhir di tangan monster kosmis seperti " wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}