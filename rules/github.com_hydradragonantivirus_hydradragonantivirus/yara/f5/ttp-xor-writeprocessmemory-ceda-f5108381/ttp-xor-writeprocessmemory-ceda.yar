rule TTP_XOR_WriteProcessMemory_ceda {
  strings:
    $key_ceda = { 99 a8 [2] ab 8a [2] ad bf [2] 83 bf [2] bc a3 }

  condition:
    any of them
}