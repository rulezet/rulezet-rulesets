rule Methodology_Mutation_FLIPFLOP_Windows_Pipe_Functions {
  meta:
    author = "Stairwell"
    description = "Searching for PE files with mutations of odd, rare, or interesting string equities. This string mutation takes its inspiration from APT29/CozyBear malware family called FLIPFLOP because it reads in a subfile but reverses every two bytes."
    hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
  strings:
    $CallNamedPipe_flipflop = "aCllaNemPdpie" nocase
    $ConnectNamedPipe_flipflop = "oCnnceNtmadeiPep" nocase
    $CreateNamedPipe_flipflop = "rCaeetaNemPdpie" nocase
    $CreatePipe_flipflop = "rCaeetiPep" nocase
    $DisconnectNamedPipe_flipflop = "iDcsnoentcaNemPdpie" nocase
    $GetNamedPipeClientComputerName_flipflop = "eGNtmadeiPeplCeitnoCpmtureaNem" nocase
    $GetNamedPipeClientProcessId_flipflop = "eGNtmadeiPeplCeitnrPcoseIsd" nocase
    $GetNamedPipeClientSessionId_flipflop = "eGNtmadeiPeplCeitneSssoiInd" nocase
    $GetNamedPipeHandleState_flipflop = "eGNtmadeiPepaHdneltStae" nocase
    $GetNamedPipeInfo_flipflop = "eGNtmadeiPepnIof" nocase
    $GetNamedPipeServerProcessId_flipflop = "eGNtmadeiPepeSvrrerPcoseIsd" nocase
    $GetNamedPipeServerSessionId_flipflop = "eGNtmadeiPepeSvrreeSssoiInd" nocase
    $PeekNamedPipe_flipflop = "ePkeaNemPdpie" nocase
    $SetNamedPipeHandleState_flipflop = "eSNtmadeiPepaHdneltStae" nocase
    $TransactNamedPipe_flipflop = "rTnaastcaNemPdpie" nocase
    $WaitNamedPipe_flipflop = "aWtiaNemPdpie" nocase
  condition:
    filesize < 15MB and uint16be(0) == 0x4d5a and 1 of them
}