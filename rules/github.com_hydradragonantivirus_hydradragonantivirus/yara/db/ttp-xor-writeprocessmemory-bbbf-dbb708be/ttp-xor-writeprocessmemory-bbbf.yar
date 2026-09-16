rule TTP_XOR_WriteProcessMemory_bbbf {
  strings:
    $key_bbbf = { ec cd [2] de ef [2] d8 da [2] f6 da [2] c9 c6 }

  condition:
    any of them
}