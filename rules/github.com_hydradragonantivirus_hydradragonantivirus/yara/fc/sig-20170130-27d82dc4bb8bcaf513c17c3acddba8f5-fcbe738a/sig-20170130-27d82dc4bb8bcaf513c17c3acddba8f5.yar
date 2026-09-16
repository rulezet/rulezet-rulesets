rule sig_20170130_27d82dc4bb8bcaf513c17c3acddba8f5 {
  meta:
    description = "datamaliciousorder - file 20170130_27d82dc4bb8bcaf513c17c3acddba8f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff9ecc2ae4460c06c5fb8cb9d388a8ee2af060b6dab45b4bc3d9600ed0ac4bf0"

  strings:
    $s1  = "if ([true, \"vatp290ams\", \"go637ilfi\", \"sop338zymo\", true, true, new Function([true, true, true, \"elm473ofemv\", true, tru" ascii
    $s2  = "8ocxi\", true, [\"Get\", true], true, \"gyl303flaqtu\"][8][0] + [[\"Tem\", true], \"edifj594eclogp\", true, true, \"ud328tuxh\"," ascii
    $s3  = "kufifkatudakiconxufbagilrivuzimoxyfbendujunxajvyqnabgakzofragernicipulexkiqnongyxzufoszajpewusugrihjefzisohigoncazwypqyzuhbabotc" ascii
    $s4  = "satmelnocdikkojyhuwdyxebamjowgukfincubbaszymvyvzojefidvapqunuqiqicgobpiwobbiwomfircepixdasuhadsatoqachizleboxucihuvywcujijirluqy" ascii
    $s5  = "mopufysawoldupusyjledlatqivjalhiduxyqlihvykcywujurvidugofovajjiwuvepehfepilobyrziqtabyltajjennuvyklocenyhbyzutsicopfiblewuxbyzuz" ascii
    $s6  = ", \"aluw469xa\", true, true, true, true, \"unywk606elogv\", \"fyx814swuko\"][0][1] + [\"ka895ij\", true, [\"eof\", \"jy171hqymp" ascii
    $s7  = " true, true, \"yr910ide\", \"asv781joqv\", true, \"zdi882dopvu\"][0][0] + [\"medq403fit\", \"ywt112ag\", \"zem361rfa\", \"na339k" ascii
    $s8  = "60bewre\", true, [\"odihq789inr\", \"Get\"], \"mrinu118cqo\", true, true, \"yndi484hoha\", true, true][5][1] + [\"ufi232swirwi\"" ascii
    $s9  = "kufifkatudakiconxufbagilrivuzimoxyfbendujunxajvyqnabgakzofragernicipulexkiqnongyxzufoszajpewusugrihjefzisohigoncazwypqyzuhbabotc" ascii
    $s10 = "cbysusanesymatqajaxipfabcedbunahcugmoqvavcarhuhybzohdylcohydpihekarwesvykvyvtyhcasefmavitfidacvettuspysdoxsifercuduxyfvunkogijzy" ascii
    $s11 = "kufifkatudakiconxufbagilrivuzimoxyfbendujunxajvyqnabgakzofragernicipulexkiqnongyxzufoszajpewusugrihjefzisohigoncazwypqyzuhbabotc" ascii
    $s12 = " \"ivid339cqug\", \"cecfi789yv\", \"kty915gol\", \"ap684daz\", \"ixv658pudy\", true, \"evw899rit\", true, \"ed190urun\", true][0" ascii
    $s13 = "kufifkatudakiconxufbagilrivuzimoxyfbendujunxajvyqnabgakzofragernicipulexkiqnongyxzufoszajpewusugrihjefzisohigoncazwypqyzuhbabotc" ascii
    $s14 = "tuspysdoxsifercuduxyfvunkogijzysiwopsowkuhvypyznuzuzorwanxenuxogmycubhugigcizmilo8[[true, true, true, true, true, [\"rbyg189effu" ascii
    $s15 = "tuspysdoxsifercuduxyfvunkogijzysiwopsowkuhvypyznuzuzorwanxenuxogmycubhugigcizmilo8[[true, true, true, [true, \"Clo\"], true, tru" ascii
    $s16 = "cbysusanesymatqajaxipfabcedbunahcugmoqvavcarhuhybzohdylcohydpihekarwesvykvyvtyhcasefmavitfidacvettuspysdoxsifercuduxyfvunkogijzy" ascii
    $s17 = "kufifkatudakiconxufbagilrivuzimoxyfbendujunxajvyqnabgakzofragernicipulexkiqnongyxzufoszajpewusugrihjefzisohigoncazwypqyzuhbabotc" ascii
    $s18 = "kufifkatudakiconxufbagilrivuzimoxyfbendujunxajvyqnabgakzofragernicipulexkiqnongyxzufoszajpewusugrihjefzisohigoncazwypqyzuhbabotc" ascii
    $s19 = "tuspysdoxsifercuduxyfvunkogijzysiwopsowkuhvypyznuzuzorwanxenuxogmycubhugigcizmilo8[[true, true, \"uhix948pda\", \"yst606ubi\", " ascii
    $s20 = "tuspysdoxsifercuduxyfvunkogijzysiwopsowkuhvypyznuzuzorwanxenuxogmycubhugigcizmilo8[[true, true, true, [true, \"Sa\"], true, true" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}