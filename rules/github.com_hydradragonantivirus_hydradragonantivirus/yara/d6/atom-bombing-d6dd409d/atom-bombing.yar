import "pe"
rule Atom_Bombing {
  meta:
    author      = "McAfee ATR - Thomas Roccia - @fr0gger_ "
    description = "Detect AtomBombing Injection"
    reference   = "https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows"
    mitre_id    = "T1055"

  strings:
    $var1 = "GlobalAddAtom" nocase
    $var2 = "GlobalGetAtomName" nocase
    $var3 = "QueueUserAPC" nocase
    $var4 = "NtQueueApcThread" nocase
    $var5 = "NtSetContextThread" nocase

  condition:
    uint16(0) == 0x5A4D and (all of them or
      pe.imports("Kernel32.dll", "GlobalAddAtom") and
      pe.imports("Kernel32.dll", "GlobalGetAtomName") and
      pe.imports("Kernel32.dll", "QueueUserAPC"))
}