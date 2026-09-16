rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_aqgEuSk_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aqgEuSk_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b19e50c036f22e03599acb09e8fd056f09a934b1efcc899bf53da2f398f492"

  strings:
    $s1  = "Bamiko. Si cepuxubuga. Kuyagetacuco ceka. Kobecofoma. Pavumehupomo soso ru. Hibilonubahopi luduwo ko. Cetuvuro vulutiruhuxeni mu" ascii
    $s2  = "<Zoku sigojo fagoyayepeyobi siwiyujilefeza di. Zofixu malanuxide sekabe. Kuhifelosura dogeha beboyija corekumedu. Zijugatibexa g" ascii
    $s3  = "Ciwocojufa. Nisi. Dujuvunaleyugi yugokulezafetu kuli renavivuveci. Yubopivokuroge ci ve. Hamozaviboloju caru. Pusiyawifivuko wib" ascii
    $s4  = "dudamovu. Loheyepu niheboruzude dahevaxena. Dice mi. Zexijedicokepo. Yizeponuva pelalinukewi. Fi ruzice gamamokeru kogajagijace " ascii
    $s5  = "Bamiko. Si cepuxubuga. Kuyagetacuco ceka. Kobecofoma. Pavumehupomo soso ru. Hibilonubahopi luduwo ko. Cetuvuro vulutiruhuxeni mu" ascii
    $s6  = "Mobizaravomi kovi hebepicora xizufole foxuyu. Ratenu. Nexecifacu livi jideyizi mapinecirelilu zape. Sugebu luxe. Mufedecamami pu" ascii
    $s7  = " hurutetetehoyu xu xetihologupoyu jejudovo. Decupawazepofu sogega kacuzucayi yolifexi moho. Zaxaye fapoye du catebacebiba. Viwuj" ascii
    $s8  = " gupotitokaro woyezuhahuxo. Wepe. Sa mederaveyavu. Ruzolehiyali jowasezeke refimijobololo. Vobagosu. Wocubi rotupozesinika. Sabe" ascii
    $s9  = "yazahudikopa mehobaguhu puzowu. Pojiki rujivimaxemu cofu. Sugocu pudu zezeyuweredo. Ropuyupadirapi hihi yi covoru megu. Kopedori" ascii
    $s10 = "aga. Wepo derihaconoco. Tado biti cecinomahe. Fefe wawefosafimeri pinolile deruxohaloha nita. Ka fisepuhakute. Fepikunizukewu ci" ascii
    $s11 = "Jete tinewiyu kefobaxoru" fullword wide
    $s12 = "WNaxabebemeyu dakikumaveyiyo zevonomidu fagitagujihi cute vi zogokofelenope vefevelujidu" fullword wide
    $s13 = "Copyright (C) 2017, fockertoub" fullword wide
    $s14 = "Nm cannot be run in DOS mode." fullword ascii
    $s15 = "oyibiveja pile. Dusubijafe. Fopojatica bine howepiloyayayu kazavaca. Misiwo fewanogu gepajipide si zevolaya. Sukezahegi goreliha" ascii
    $s16 = "!This " fullword ascii
    $s17 = "eboni golatonovudo. Kuboyo kozabivo. Capenucahe go fozi lava. Mevu tubeyu. Boxisidewoho fafe bakaji cawifuzusa gadikofaxa. Nomig" ascii
    $s18 = "ejo. Hidu sotolema carapu noho. Vuji rusufigavuhi waluluwaloriji tera. Zugatisoxidaco vuni nofa. Jetiba gawewedi. Hawolaxalo lon" ascii
    $s19 = "gota letunu furawe cadi yotuvo. Nuhiba zujijukaraka lebumagagipifo hahugu. Ni bivu vahelocuficihe depafovovu. Zunivofusaroti yef" ascii
    $s20 = "yo ni. Ducofuki vulare furajecoxacu picaluzixi. Dupaveruba doyunubero kasamijo fodila. Ratadapaki lija canidi. Kajisibuyunija wu" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}