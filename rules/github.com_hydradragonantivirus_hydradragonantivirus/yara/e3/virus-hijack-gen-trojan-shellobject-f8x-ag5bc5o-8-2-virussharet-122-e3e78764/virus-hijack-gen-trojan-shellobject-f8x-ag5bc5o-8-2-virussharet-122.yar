import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_8_2_VirusShareT_122 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_8_2.vir, VirusShareTrojanSiggen817711.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a0f644cb37624ab9f60b7e6706582255a016628c8c78c94d829ecc3ac9429f6"
    hash2       = "bd6de74eabbdb72321816001868b945a08876fea3495d6f5f7af2598923b5ab1"

  strings:
    $s1  = "NE\\Benutzername.Fehler beim Laden oder Anlegen einer INI-Datei im TEMP-Verzeichnis des Benutzers.ISNetAPI.dll ist nicht geladen" ascii
    $s2  = "NE\\Benutzername.Fehler beim Laden oder Anlegen einer INI-Datei im TEMP-Verzeichnis des Benutzers.ISNetAPI.dll ist nicht geladen" ascii
    $s3  = "RPURLUPDATEINFOhttp://helpx.adobe.com/de/reader.htmlAcroIEHelper_DescriptionAdobe PDF ReaderAppsInUseSilentAbortEs wird ein Vorg" ascii
    $s4  = "bertragungsmeldungcaRemoveVRootsARPREADMELiesmich.htmARPCONTACTKundendienstARPHELPLINKhttp://www.adobe.com/de/support/main.htmlA" ascii
    $s5  = "e: [3] ByteProcessAbcpyAbcpy.ini-Datei wird verarbeitet.ProcessComponentsRegistrierung der Komponente(n) wird aktualisiertRMCCPS" ascii
    $s6  = "e: [3] ByteProcessAbcpyAbcpy.ini-Datei wird verarbeitet.ProcessComponentsRegistrierung der Komponente(n) wird aktualisiertRMCCPS" ascii
    $s7  = "her. Aktualisieren Sie Internet Explorer. Besuchen Sie dazu die Website www.microsoft.com.LC_UNSUPPORTED_OSLC_UNSUPPORTED_OS_1Di" ascii
    $s8  = "r die ISNetApi.dll muss NetApi32.DLL einwandfrei geladen sein und das Betriebssystem muss auf NT basieren.Server konnte nicht ge" ascii
    $s9  = "gen.Fehler beim Erstellen der XML-Datei [2]. [3]Fehler beim Laden der Server.Fehler beim Laden von NetApi32.DLL. F" fullword ascii
    $s10 = "r die ISNetApi.dll muss NetApi32.DLL einwandfrei geladen sein und das Betriebssystem muss auf NT basieren.Server konnte nicht ge" ascii
    $s11 = "r ReaderARMNewFeature1ReaderProgramFilesAdobe Reader-ProgrammdateienDieses Feature besteht aus Reader-Programmdateien.Reader_Big" ascii
    $s12 = "r die Registrierung der Serviced Components von Microsoft (R) .NET muss Microsoft (R) .NET Framework installiert sein.SQL-Skript" ascii
    $s13 = "_FeaturesIn der Vollversion von Adobe Reader enthaltene FunktionenReader (Vollversion) - FunktionssatzAccessibility_PluginsBarri" ascii
    $s14 = "r die Registrierung der Serviced Components von Microsoft (R) .NET muss Microsoft (R) .NET Framework installiert sein.SQL-Skript" ascii
    $s15 = "glich.Die folgenden Anwendungen sollten geschlossen werden, bevor Sie die Installationen fortsetzen:Es wurde keine Installation " ascii
    $s16 = "r das Suchen nach oder Verbinden mit Datenbank-Servern muss MDAC installiert sein.  Setup wird jetzt beendet.Fehler beim Install" ascii
    $s17 = "her. Aktualisieren Sie Internet Explorer. Besuchen Sie dazu die Website www.microsoft.com.LC_UNSUPPORTED_OSLC_UNSUPPORTED_OS_1Di" ascii
    $s18 = "ERROR_DEFRAG_ADTEMPLATE[1]% des Vorgangs abgeschlossenERROR_DEFRAG_MSGLeistung wird optimiert...ERROR_MIN_OVER_BIGSetup hat eine" ascii
    $s19 = "gen, um IIS Virtual Roots zu konfigurieren.Es konnte keine Verbindung zum [2] hergestellt werden [3]. [4]Fehler beim Abrufen des" ascii
    $s20 = "ltere Version von [2] kann nicht entfernt werden. Setzen Sie sich mit Ihrem technischen Supportpersonal in Verbindung. {{Systemf" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "67533f79a87f4ce08c671dedbb7cb801" and (8 of them)
    ) or (all of them)
}