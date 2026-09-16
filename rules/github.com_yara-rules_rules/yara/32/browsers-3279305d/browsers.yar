rule Browsers
{
    meta:
        description = "Contains references to internet browsers"
        author = "Ivan Kwiatkowski (@JusticeRage)"
    strings:
        $ie = "iexplore.exe" nocase wide ascii
        $ff = "firefox.exe" nocase wide ascii
        $ff_key = "key3.db"
        $ff_log = "signons.sqlite"
        $chrome = "chrome.exe" nocase wide ascii
            condition:
        any of them
}