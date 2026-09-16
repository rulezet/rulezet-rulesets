rule TTP_XOR_WriteProcessMemory_9bbf {
  strings:
    $key_9bbf = { cc cd [2] fe ef [2] f8 da [2] d6 da [2] e9 c6 }

  condition:
    any of them
}