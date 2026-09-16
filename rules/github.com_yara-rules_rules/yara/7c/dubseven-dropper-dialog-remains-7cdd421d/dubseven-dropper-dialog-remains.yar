rule dubseven_dropper_dialog_remains
{
   
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Searches for related dialog remnants. How rude."
    
    strings:
        $dia1 = "fuckMessageBox 1.0" wide
        $dia2 = "Rundll 1.0" wide
        
    condition:
                uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and any of them
}