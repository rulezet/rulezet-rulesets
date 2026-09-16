rule APC_Inject {
  meta:
    author      = "McAfee ATR - Thomas Roccia - @fr0gger_ "
    description = "Detect APC Injection"
    mitre_id    = "T1055"

  strings:
    $func1 = "NtQueueApcThread" nocase
    $func2 = "NtResumeThread" nocase
    $func3 = "NTTestAlert" nocase
    $func4 = "QueueUserApc" nocase

  condition:
    uint16(0) == 0x5A4D and ($func1 and $func2 or all of them)
}