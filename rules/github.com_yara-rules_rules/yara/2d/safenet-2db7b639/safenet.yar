rule SafeNet : Family
{
    meta:
        description = "SafeNet family"
        
    condition:
        SafeNetCode or SafeNetStrings
        
}