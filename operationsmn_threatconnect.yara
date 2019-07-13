// https://www.novetta.com/wp-content/uploads/2014/11/ThreatConnect.txt

rule APT_ZXShell_VFW
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$D = "DoActionRDSRV" wide ascii
	$h = /h:\\Prj20[0-9]{2}/ nocase wide ascii // 'h:\Prj2012'
	$R = "ReleaseTest\\Remote" nocase wide ascii
	$R1 = "RemoteDeskTop.dll" wide ascii
	$z = "zxapp-console\\" nocase wide ascii
condition:
	any of them
}

rule ZXProxy
{
meta:
	author = "ThreatConnect Intelligence Research Team"

strings:
	$C = "\\Control\\zxplug" nocase wide ascii
	$h = "http://www.facebook.com/comment/update.exe" wide ascii
	$S = "Shared a shell to %s:%s Successfully" nocase wide ascii
condition:
	any of them
}

rule APT_Hikit_msrv
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$m = "\x00msrv.dll\x00Dll" wide ascii
condition:
	any of them
}

rule APT_Derusbi_Gen
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$2 = "273ce6-b29f-90d618c0" wide ascii
	$A = "Ace123dx" fullword wide ascii
	$A1 = "Ace123dxl!" fullword wide ascii
	$A2 = "Ace123dx!@#x" fullword wide ascii
	$C = "/Catelog/login1.asp" wide ascii
	$DF = "~DFTMP$$$$$.1" wide ascii
	$G = "GET /Query.asp?loginid=" wide ascii
	$L = "LoadConfigFromReg failded" wide ascii
	$L1 = "LoadConfigFromBuildin success" wide ascii
	$ph = "/photoe/photo.asp HTTP" wide ascii
	$PO = "POST /photos/photo.asp" wide ascii
	$PC = "PCC_IDENT" wide ascii
condition:
	any of them
}

rule APT_Derusbi_DeepPanda
{
meta:
	author = "ThreatConnect Intelligence Research Team"
	reference = "http://www.crowdstrike.com/sites/default/files/AdversaryIntelligenceReport_DeepPanda_0.pdf"
strings:
	$D = "Dom4!nUserP4ss" wide ascii
condition:
	$D
}

rule APT_DeputyDog_Fexel
{
meta:
	author = "ThreatConnect Intelligence Research Team"
strings:
	$180 = "180.150.228.102" wide ascii
	$0808cmd = {25 30 38 78 30 38 78 00 5C 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 [2-6] 43 00 61 00 6E 00 27 00 74 00 20 00 6F 00 70 00 65 00 6E 00 20 00 73 00 68 00 65 00 6C 00 6C 00 21}
	$cUp = "Upload failed! [Remote error code:" nocase wide ascii
	$DGGYDSYRL = "DGGYDSYRL" fullword wide ascii
	$GDGSYDLYR = "GDGSYDLYR_%" wide ascii
condition:
	any of them
}
