---
layout: post
title: "Windows Cumulative Update: Component to Binary Mapping"
date: 2026-03-10
categories:
  - Research
  - Windows Internals
  - Patch Tuesday
tags:
  - windows
  - patch-tuesday
  - reverse-engineering
  - security
---

# Windows Cumulative Update: Component to Binary Mapping

When analyzing Windows Patch Tuesday updates, one of the fundamental questions is: **which DLLs, EXEs, and SYS files belong to which WinSxS component?** This mapping is buried inside DCM-compressed manifest files within the Cumulative Update (CU) packages and isn't documented anywhere publicly.

This post provides the complete component-to-binary mapping extracted from the **November 2023 Patch Tuesday** CU (KB5032190, Windows 11 22H2/23H2, build 10.0.22621.2715), along with details on how the extraction works.

## Background: How Windows CU Packages Work

A Windows Cumulative Update `.msu` package contains:

| Format | Contents |
|--------|----------|
| **Modern (Win11 22H2+)** | PSF (delta patches) + WIM (component manifests) + SSU CAB |
| **Legacy (pre-Win11 22H2)** | PSF (delta patches) + CAB (manifests + servicing stack PEs) + SSU CAB |

The **PSF** (Patch Storage File) contains forward/reverse binary deltas that CBS (Component-Based Servicing) applies to the currently-installed PEs on disk. The **manifests** (either in WIM or CAB) describe every component being serviced — including the exact filenames and content hashes of each binary.

### DCM Manifest Decompression

Most manifests inside the CU are **DCM-compressed** (Delta Compressed Manifest). These are PA30 forward deltas that need a basis document to decompress.

The basis is a template manifest XML stored in `wcp.dll` (Windows Component Platform) as resource type 614, name #1. The decompression uses `msdelta.dll`'s `ApplyDeltaB` function:

```
DCM manifest (PA30 delta) + wcp.dll resource 614#1 (basis) → full manifest XML
```

For KB5032190: **23,759 out of 23,830** manifests were DCM-compressed. All decompressed successfully with zero parse errors.

### Manifest XML Structure

Each decompressed manifest contains `<file>` elements in the `urn:schemas-microsoft-com:asm.v3` namespace:

```xml
<assembly xmlns="urn:schemas-microsoft-com:asm.v3">
  <assemblyIdentity name="Microsoft-Windows-NTFS"
    version="10.0.22621.2715" processorArchitecture="amd64"
    publicKeyToken="31bf3856ad364e35" />
  <file name="ntfs.sys" sourceName="ntfs.sys"
    importPath="$(runtime.system32)\drivers\">
    <hash>
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256" />
      <DigestValue>...</DigestValue>
    </hash>
  </file>
</assembly>
```

The `<file name="...">` attribute gives the binary filename, and the `DigestValue` provides a SHA256 content hash used for integrity verification and diff comparison.

## Extraction Results

**Source**: KB5032190 (November 2023 Patch Tuesday, Windows 11 22H2)

| Metric | Count |
|--------|-------|
| Total manifests | 23,830 |
| DCM-compressed | 23,759 (100% decompressed) |
| Manifests with `<file>` elements | 15,367 |
| Total `<file>` elements | 31,801 |
| Unique PE binaries (.dll/.exe/.sys) | 3,654 |
| Unique component IDs | 3,172 |

### Diffing Against KB5031354 (October 2023)

Comparing the DigestValue hashes between KB5032190 (Nov fix) and KB5031354 (Oct superseded):

| Category | Count |
|----------|-------|
| **Changed** (different hash) | 3,393 |
| **Added** (new in Nov) | 43 |
| **Removed** | 0 |
| **Unchanged** (identical hash) | 221 |

> Note: CU updates are cumulative — every binary gets a version bump even if only the version resource changed. The 3,393 "changed" includes both security fixes and routine version bumps. Components at version `.2715` are the ones with actual **security fixes** in this specific November patch. Components at `.2506` are carried forward from a prior CU.

---

## Security-Critical Components

### Kernel & Executive

| Component ID | Binaries | Version |
|-------------|----------|---------|
| `amd64_microsoft-windows-os-kernel` | **ntoskrnl.exe** | 10.0.22621.**2715** |
| `amd64_microsoft-windows-commonlog` | **clfs.sys** | 10.0.22621.**2715** |
| `amd64_microsoft-windows-cng` | **cng.sys** | .2506 |
| `amd64_microsoft-windows-codeintegrity` | **ci.dll** | .2506 |
| `amd64_microsoft-onecore-codeintegrity-secure` | **skci.dll** | .2506 |
| `amd64_microsoft-windows-filtermanager-core` | **fltmgr.sys** | .2506 |
| `amd64_microsoft-onecore-..isolated-usermode-kernel` | **securekernel.exe** | .2506 |
| `amd64_microsoft-onecore-..isolated-usermode-kernel-la57` | **securekernella57.exe** | .2506 |

### Win32k Subsystem (GDI/USER)

| Component ID | Binaries | Version |
|-------------|----------|---------|
| `amd64_microsoft-windows-win32k` | **win32k.sys**, **win32kfull.sys**, win32u.dll | .2506 |
| `amd64_microsoft-windows-win32kbase` | **win32kbase.sys** | .2506 |
| `amd64_microsoft-windows-win32ksgd` | **win32ksgd.sys** | .2506 |
| `amd64_microsoft-windows-lddmcore` | cdd.dll, **dxgkrnl.sys**, dxgmms1.sys, dxgmms2.sys | .2506 |
| `amd64_microsoft-windows-d..wmanager-compositor` | **dwmcore.dll** | .**2715** |
| `amd64_microsoft-windows-gdi32` | **gdi32.dll** | .2506 |
| `amd64_microsoft-windows-gdi32full` | **gdi32full.dll** | .2506 |
| `amd64_microsoft-windows-user32` | **user32.dll** | .2506 |

### Networking

| Component ID | Binaries | Version |
|-------------|----------|---------|
| `amd64_microsoft-windows-tcpip-driver` | fwpkclnt.sys, **tcpip.sys**, tcpipreg.sys | .2506 |
| `amd64_microsoft-windows-http` | **http.sys** | .2506 |
| `amd64_microsoft-windows-http-api` | httpapi.dll | .2506 |
| `amd64_microsoft-windows-ndis-minwin` | **ndis.sys** | .2506 |
| `amd64_microsoft-windows-winsock-core` | **afd.sys** | .2506 |
| `amd64_microsoft-windows-tdi-over-tcpip` | **tdx.sys** | .2506 |

### File Systems & SMB

| Component ID | Binaries | Version |
|-------------|----------|---------|
| `amd64_microsoft-windows-ntfs` | **ntfs.sys** | .**2715** |
| `amd64_microsoft-windows-rdbss` | **rdbss.sys** | .2506 |
| `amd64_microsoft-windows-smbminirdr` | **mrxsmb.sys** | .2506 |
| `amd64_microsoft-windows-smb10-minirdr` | mrxsmb10.sys | .2506 |
| `amd64_microsoft-windows-smb20-minirdr` | mrxsmb20.sys | .2506 |
| `amd64_microsoft-windows-smbserver-v1` | **srv.sys** | .2506 |
| `amd64_microsoft-windows-smbserver-v2` | **srv2.sys** | .2506 |
| `amd64_microsoft-windows-smbserver-common` | srvnet.sys | .2506 |

### Authentication & Cryptography

| Component ID | Binaries | Version |
|-------------|----------|---------|
| `amd64_microsoft-windows-security-kerberos` | **kerberos.dll** | .**2715** |
| `amd64_microsoft-windows-lsa` | ksecpkg.sys, **lsasrv.dll**, offlinelsa.dll | .2506 |
| `amd64_microsoft-windows-lsa-minwin` | **lsass.exe**, sspicli.dll, sspisrv.dll | .2506 |
| `amd64_microsoft-windows-security-schannel` | **schannel.dll** | .2506 |
| `amd64_microsoft-windows-security-netlogon` | **netlogon.dll** | .2506 |
| `amd64_microsoft-windows-dpapisrv-dll` | **dpapisrv.dll** | .2506 |

### Hyper-V

| Component ID | Binaries | Version |
|-------------|----------|---------|
| `amd64_microsoft-hyper-v-drivers-hypervisor` | **hvax64.exe**, **hvix64.exe**, hvloader.dll, kdhvcom.dll | .**2715** |
| `amd64_hyperv-compute-host-service` | vmcompute.exe | .2506 |
| `amd64_hyperv-computelib-core` | computecore.dll | .2506 |
| `amd64_microsoft-hyper-v-vstack-vsmb` | vmsmb.dll, vmusrv.dll | .2506 |

### RPC & COM

| Component ID | Binaries | Version |
|-------------|----------|---------|
| `amd64_microsoft-windows-rpc-local` | **rpcrt4.dll** | .2506 |
| `amd64_microsoft-windows-rpc-kernel` | **msrpc.sys** | .2506 |
| `amd64_microsoft-windows-com-base-qfe-rpcss` | **rpcss.dll** | .2506 |
| `amd64_microsoft-windows-com-base-qfe-ole32` | **ole32.dll** | .2506 |
| `amd64_microsoft-windows-com-base` | combase.dll, wincorlib.dll, wintypes.dll | .2506 |

---

## Full Component-to-Binary Mapping

<details>
<summary><strong>Click to expand full mapping (3,172 components)</strong></summary>

> Format: `component_id [version] -> binary1, binary2, ...`
> Components marked with a star are at version .2715 (security-patched in this specific CU).

```
amd64_aagwrapper_31bf3856ad364e35 [10.0.22621.2506] -> aagwrapper.dll
amd64_azurecomputehost-wdsclientapi_31bf3856ad364e35 [10.0.22621.2506] -> wdsclientapi.dll
amd64_bsdtar_31bf3856ad364e35 [10.0.22621.2506] -> tar.exe
amd64_curl_31bf3856ad364e35 [10.0.22621.2715] * -> curl.exe
amd64_desktop_shell-search-srchadmin_31bf3856ad364e35 [7.0.22621.2506] -> srchadmin.dll
amd64_dsprop_31bf3856ad364e35 [10.0.22621.2506] -> dsprop.dll
amd64_dual_1394.inf_31bf3856ad364e35 [10.0.22621.2506] -> 1394ohci.sys
amd64_dual_acpi.inf_31bf3856ad364e35 [10.0.22621.2506] -> acpi.sys
amd64_dual_acpidev.inf_31bf3856ad364e35 [10.0.22621.2506] -> acpidev.sys
amd64_dual_acxhdaudiop.inf_31bf3856ad364e35 [10.0.22621.2506] -> acxhdaudio.sys
amd64_dual_basicrender.inf_31bf3856ad364e35 [10.0.22621.2506] -> basicrender.sys
amd64_dual_bth.inf_31bf3856ad364e35 [10.0.22621.2715] * -> bthenum.sys, bthmini.sys, bthport.sys, bthusb.sys
amd64_dual_bthleenum.inf_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.bluetooth.legacy.leenumerator.sys
amd64_dual_bthmtpenum.inf_31bf3856ad364e35 [10.0.22621.2506] -> bthmtpenum.sys
amd64_dual_bthpan.inf_31bf3856ad364e35 [10.0.22621.2506] -> bthpan.sys
amd64_dual_bthprint.inf_31bf3856ad364e35 [10.0.22621.2506] -> bthprint.sys
amd64_dual_cpu.inf_31bf3856ad364e35 [10.0.22621.2506] -> amdk8.sys, amdppm.sys, intelppm.sys, processr.sys
amd64_dual_dc1-controller.inf_31bf3856ad364e35 [10.0.22621.2506] -> dc1-controller.sys
amd64_dual_disk.inf_31bf3856ad364e35 [10.0.22621.2506] -> disk.sys
amd64_dual_ehstortcgdrv.inf_31bf3856ad364e35 [10.0.22621.2506] -> ehstortcgdrv.sys
amd64_dual_eyegazeioctl.inf_31bf3856ad364e35 [10.0.22621.2506] -> eyegazeioctl.sys
amd64_dual_hdaudbus.inf_31bf3856ad364e35 [10.0.22621.2506] -> hdaudbus.sys
amd64_dual_hdaudio.inf_31bf3856ad364e35 [10.0.22621.2506] -> hdaudio.sys
amd64_dual_helloface.inf_31bf3856ad364e35 [10.0.22621.2506] -> facedetectorresources.dll, faceprocessor.dll, faceprocessorcore.dll, facerecognitionengineadapter.dll, facerecognitionengineadapterresources.dll, facerecognitionengineadapterresources_v2.dll, facerecognitionengineadapterresources_v3.dll, facerecognitionengineadapterresources_v4.dll, facerecognitionengineadapterresources_v5.dll, facerecognitionengineadapterresourcescore.dll, facerecognitionengineadapterresourcessecure.dll, facerecognitionsensoradapter.dll, facerecognitionsensoradapterresources.dll, facerecognitionsensoradaptervsm.dll, facerecognitionsensoradaptervsmsecure.dll, facetrackerinternal.dll, helloface.dll
amd64_dual_hidbth.inf_31bf3856ad364e35 [10.0.22621.2506] -> hidbth.sys
amd64_dual_hidbthle.inf_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.bluetooth.profiles.hidovergatt.dll
amd64_dual_hidi2c.inf_31bf3856ad364e35 [10.0.22621.2506] -> hidi2c.sys
amd64_dual_hidspi_km.inf_31bf3856ad364e35 [10.0.22621.2506] -> hidspi.sys
amd64_dual_hidtelephonydriver.inf_31bf3856ad364e35 [10.0.22621.2506] -> hidtelephony.dll
amd64_dual_hidvhf.inf_31bf3856ad364e35 [10.0.22621.2506] -> vhf.sys
amd64_dual_hvservice.inf_31bf3856ad364e35 [10.0.22621.2506] -> hvservice.sys
amd64_dual_input.inf_31bf3856ad364e35 [10.0.22621.2506] -> hidclass.sys, hidparse.sys, hidusb.sys
amd64_dual_intelpep.inf_31bf3856ad364e35 [10.0.22621.2506] -> intelpep.sys
amd64_dual_intelpmt.inf_31bf3856ad364e35 [10.0.22621.2506] -> intelpmt.sys
amd64_dual_ipmidrv.inf_31bf3856ad364e35 [10.0.22621.2506] -> ipmidrv.sys
amd64_dual_iscsi.inf_31bf3856ad364e35 [10.0.22621.2506] -> iscsilog.dll, msiscsi.sys
amd64_dual_mdmbtmdm.inf_31bf3856ad364e35 [10.0.22621.2506] -> bthmodem.sys
amd64_dual_mf.inf_31bf3856ad364e35 [10.0.22621.2506] -> mf.sys
amd64_dual_miradisp.inf_31bf3856ad364e35 [10.0.22621.2506] -> miradisp.dll
amd64_dual_monitor.inf_31bf3856ad364e35 [10.0.22621.2506] -> monitor.sys
amd64_dual_msgpiowin32.inf_31bf3856ad364e35 [10.0.22621.2506] -> msgpiowin32.sys
amd64_dual_mshdc.inf_31bf3856ad364e35 [10.0.22621.2506] -> atapi.sys, ataport.sys, intelide.sys, pciide.sys, pciidex.sys, storahci.sys
amd64_dual_narrfltr.inf_31bf3856ad364e35 [10.0.22621.2506] -> narrfltr.sys
amd64_dual_ntprint.inf_31bf3856ad364e35 [10.0.22621.2506] -> mxdwdrv.dll, pcl4res.dll, pcl5eres.dll, pcl5ures.dll, pclxl.dll, pjlmon.dll, ps5ui.dll, pscript5.dll, unidrv.dll, unidrvui.dll, unires.dll
amd64_dual_ntprint4.inf_31bf3856ad364e35 [10.0.22621.2506] -> msxpspcl6.dll, msxpsps.dll, pclmrenderfilter.dll, pdfrenderfilter.dll, pwgrrenderfilter.dll, v3hostingfilter.dll
amd64_dual_oposdrv.inf_31bf3856ad364e35 [10.0.22621.2506] -> oposdrv.dll
amd64_dual_pci.inf_31bf3856ad364e35 [10.0.22621.2506] -> pci.sys
amd64_dual_perceptionsimulationheadset.inf_31bf3856ad364e35 [10.0.22621.2506] -> perceptionsimulationheadset.dll
amd64_dual_pmem.inf_31bf3856ad364e35 [10.0.22621.2506] -> pmem.sys
amd64_dual_prnge001.inf_31bf3856ad364e35 [10.0.22621.2506] -> ok9ibres.dll, tty.dll, ttyres.dll, ttyui.dll
amd64_dual_prnms002.inf_31bf3856ad364e35 [10.0.22621.2506] -> fxsapi.dll, fxsdrv.dll, fxsres.dll, fxstiff.dll, fxsui.dll, fxswzrd.dll
amd64_dual_prnms003.inf_31bf3856ad364e35 [10.0.22621.2715] * -> printconfig.dll
amd64_dual_rdpbus.inf_31bf3856ad364e35 [10.0.22621.2506] -> rdpbus.sys
amd64_dual_rdpidd.inf_31bf3856ad364e35 [10.0.22621.2506] -> rdpidd.dll
amd64_dual_rhproxy.inf_31bf3856ad364e35 [10.0.22621.2506] -> rhproxy.sys
amd64_dual_routepolicy.inf_31bf3856ad364e35 [10.0.22621.2506] -> routepolicy.sys
amd64_dual_sbp2.inf_31bf3856ad364e35 [10.0.22621.2506] -> sbp2port.sys
amd64_dual_scmbus.inf_31bf3856ad364e35 [10.0.22621.2506] -> scmbus.sys
amd64_dual_sdstor.inf_31bf3856ad364e35 [10.0.22621.2506] -> sdstor.sys
amd64_dual_sensorshidclassdriver.inf_31bf3856ad364e35 [10.0.22621.2506] -> sensorshid.dll
amd64_dual_spaceport.inf_31bf3856ad364e35 [10.0.22621.2506] -> spacedump.sys, spaceport.sys
amd64_dual_sti.inf_31bf3856ad364e35 [10.0.22621.2506] -> scsiscan.sys, serscan.sys, usbscan.sys, wiafbdrv.dll, wsdscan.sys
amd64_dual_stornvme.inf_31bf3856ad364e35 [10.0.22621.2506] -> stornvme.sys
amd64_dual_storufs.inf_31bf3856ad364e35 [10.0.22621.2506] -> storufs.sys
amd64_dual_tdibth.inf_31bf3856ad364e35 [10.0.22621.2506] -> rfcomm.sys
amd64_dual_tpm.inf_31bf3856ad364e35 [10.0.22621.2506] -> tpm.sys
amd64_dual_tpmvsc.inf_31bf3856ad364e35 [10.0.22621.2506] -> virtualsmartcardreader.dll
amd64_dual_tsusbhub.inf_31bf3856ad364e35 [10.0.22621.2506] -> tsusbhub.sys
amd64_dual_uaspstor.inf_31bf3856ad364e35 [10.0.22621.2506] -> uaspstor.sys
amd64_dual_ucmucsiacpiclient.inf_31bf3856ad364e35 [10.0.22621.2506] -> ucmucsiacpiclient.sys
amd64_dual_ufxchipidea.inf_31bf3856ad364e35 [10.0.22621.2506] -> ufxchipidea.sys
amd64_dual_ufxsynopsys.inf_31bf3856ad364e35 [10.0.22621.2506] -> ufxsynopsys.sys
amd64_dual_umbus.inf_31bf3856ad364e35 [10.0.22621.2506] -> umbus.sys
amd64_dual_urschipidea.inf_31bf3856ad364e35 [10.0.22621.2506] -> urschipidea.sys
amd64_dual_urssynopsys.inf_31bf3856ad364e35 [10.0.22621.2506] -> urssynopsys.sys
amd64_dual_usb.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbccgp.sys
amd64_dual_usb4devicerouter.inf_31bf3856ad364e35 [10.0.22621.2506] -> usb4devicerouter.sys
amd64_dual_usb4hostrouter.inf_31bf3856ad364e35 [10.0.22621.2506] -> usb4hostrouter.sys
amd64_dual_usb4p2pnetadapter.inf_31bf3856ad364e35 [10.0.22621.2506] -> usb4p2pnetadapter.sys
amd64_dual_usbhub3.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbhub3.sys
amd64_dual_usbncm.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbncm.sys
amd64_dual_usbport.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbd.sys, usbehci.sys, usbhub.sys, usbohci.sys, usbport.sys, usbuhci.sys
amd64_dual_usbprint.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbprint.sys
amd64_dual_usbser.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbser.sys
amd64_dual_usbvideo.inf_31bf3856ad364e35 [10.0.22621.2506] -> secureusbvideo.dll, usbvideo.sys
amd64_dual_usbxhci.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbxhci.sys, usbxhcicompanion.dll
amd64_dual_vhdmp.inf_31bf3856ad364e35 [10.0.22621.2715] * -> vhdmp.sys
amd64_dual_volmgr.inf_31bf3856ad364e35 [10.0.22621.2506] -> volmgr.sys
amd64_dual_wdma_usb.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbaudio.sys
amd64_dual_wdmaudio.inf_31bf3856ad364e35 [10.0.22621.2506] -> drmk.sys, drmkaud.sys, msapofxproxy.dll, portcls.sys, sysfxui.dll, wmalfxgfxdsp.dll
amd64_dual_winusb.inf_31bf3856ad364e35 [10.0.22621.2506] -> winusb.sys
amd64_dual_wnetvsc.inf_31bf3856ad364e35 [10.0.22621.2506] -> netvsc.sys
amd64_dual_wpdmtp.inf_31bf3856ad364e35 [10.0.22621.2506] -> wpdmtp.dll, wpdmtpbt.dll, wpdmtpdr.dll, wpdmtpip.dll, wpdmtpus.dll
amd64_dual_wstorvsc.inf_31bf3856ad364e35 [10.0.22621.2506] -> storvsc.sys
amd64_dual_wstorvsp.inf_31bf3856ad364e35 [10.0.22621.2506] -> storvsp.sys
amd64_dual_wvid.inf_31bf3856ad364e35 [10.0.22621.2715] * -> vid.sys
amd64_dual_wvkrnlintvsc.inf_31bf3856ad364e35 [10.0.22621.2506] -> vkrnlintvsc.sys
amd64_dual_wvkrnlintvsp.inf_31bf3856ad364e35 [10.0.22621.2506] -> vkrnlintvsp.sys
amd64_dual_wvmbus.inf_31bf3856ad364e35 [10.0.22621.2506] -> vmbus.sys, vmbuspipe.dll
amd64_dual_wvmbusr.inf_31bf3856ad364e35 [10.0.22621.2506] -> vmbuspiper.dll, vmbusr.sys
amd64_dual_wvpci.inf_31bf3856ad364e35 [10.0.22621.2506] -> vpci.sys
amd64_dual_xboxgip.inf_31bf3856ad364e35 [10.0.22621.2506] -> devauthe.sys, xboxgip.sys
amd64_dual_xinputhid.inf_31bf3856ad364e35 [10.0.22621.2506] -> xinputhid.sys
amd64_dual_xusb22.inf_31bf3856ad364e35 [10.0.22621.2506] -> xusb22.sys
amd64_environmentsapp.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> analog.environmentsapp.components.dll, analog.environmentsapp.services.dll, analog.shell.util.dll, environmentsapp.exe
amd64_fdssdp_31bf3856ad364e35 [10.0.22621.2506] -> fdssdp.dll
amd64_gpuvirtualizationumed_31bf3856ad364e35 [10.0.22621.2506] -> vrdumed.dll
amd64_hyperv-commandline-tool_31bf3856ad364e35 [10.0.22621.2506] -> hvc.exe
amd64_hyperv-compute-cont..utionservice-shared_31bf3856ad364e35 [10.0.22621.2506] -> cexecsvc.exe
amd64_hyperv-compute-containerdiagnosticstool_31bf3856ad364e35 [10.0.22621.2506] -> hcsdiag.exe
amd64_hyperv-compute-guestcomputeservice_31bf3856ad364e35 [10.0.22621.2506] -> vmcomputeagent.exe
amd64_hyperv-compute-host-service_31bf3856ad364e35 [10.0.22621.2506] -> vmcompute.exe
amd64_hyperv-computelib-core_31bf3856ad364e35 [10.0.22621.2506] -> computecore.dll
amd64_hyperv-computelib-legacy_31bf3856ad364e35 [10.0.22621.2506] -> vmcompute.dll
amd64_hyperv-computelib-storage_31bf3856ad364e35 [10.0.22621.2506] -> computestorage.dll
amd64_hyperv-datastore_31bf3856ad364e35 [10.0.22621.2506] -> vmdatastore.dll
amd64_hyperv-devicevirtualizationlib_31bf3856ad364e35 [10.0.22621.2506] -> vmdevicehost.dll
amd64_hyperv-handlebroker_31bf3856ad364e35 [10.0.22621.2506] -> vmhbmgmt.dll
amd64_hyperv-hvsocket-control_31bf3856ad364e35 [10.0.22621.2506] -> hvsocketcontrol.sys
amd64_hyperv-icsvcvss_31bf3856ad364e35 [10.0.22621.2506] -> icsvcvss.dll
amd64_hyperv-integrationservices_31bf3856ad364e35 [10.0.22621.2506] -> icsvc.dll, vmapplicationhealthmonitorproxy.dll, vmictimeprovider.dll
amd64_hyperv-integrationservicesext_31bf3856ad364e35 [10.0.22621.2506] -> icsvcext.dll
amd64_hyperv-isolatedvm-svc-extension_31bf3856ad364e35 [10.0.22621.2506] -> vmsvcext.sys
amd64_hyperv-networking-switch-interface_31bf3856ad364e35 [10.0.22621.2506] -> vmsif.dll, vmsifcore.dll, vmsifproxystub.dll
amd64_hyperv-proxy-onecore_31bf3856ad364e35 [10.0.22621.2506] -> vmprox.dll
amd64_hyperv-ux-featurestaging_31bf3856ad364e35 [10.0.22621.2506] -> vmstaging.dll
amd64_hyperv-virtio_31bf3856ad364e35 [10.0.22621.2506] -> vmvirtio.dll
amd64_hyperv-vmbus-proxydriver_31bf3856ad364e35 [10.0.22621.2506] -> vmbusproxy.sys
amd64_hyperv-vmbusvdev_31bf3856ad364e35 [10.0.22621.2506] -> vmbusvdev.dll
amd64_hyperv-vmchipset_31bf3856ad364e35 [10.0.22621.2506] -> vmchipset.dll
amd64_hyperv-vmcrashdump_31bf3856ad364e35 [10.0.22621.2506] -> vmcrashdump.dll
amd64_hyperv-vmdynmem_31bf3856ad364e35 [10.0.22621.2506] -> vmdynmem.dll
amd64_hyperv-vmemulateddevices_31bf3856ad364e35 [10.0.22621.2506] -> vmemulateddevices.dll
amd64_hyperv-vmfirmware-hcl_31bf3856ad364e35 [10.0.22621.2715] * -> vmfirmwarehcl.dll
amd64_hyperv-vmflexiovdev_31bf3856ad364e35 [10.0.22621.2506] -> vmflexio.dll
amd64_hyperv-vmiccore_31bf3856ad364e35 [10.0.22621.2506] -> vmiccore.dll
amd64_hyperv-vmicvdev_31bf3856ad364e35 [10.0.22621.2506] -> vmicvdev.dll
amd64_hyperv-vmkernelintvdev_31bf3856ad364e35 [10.0.22621.2506] -> vmickrnl.dll
amd64_hyperv-vmpmem_31bf3856ad364e35 [10.0.22621.2506] -> vmpmem.dll
amd64_hyperv-vmserial_31bf3856ad364e35 [10.0.22621.2506] -> vmserial.dll
amd64_hyperv-vmtpm_31bf3856ad364e35 [10.0.22621.2506] -> vmtpm.dll
amd64_hyperv-vmuidevices_31bf3856ad364e35 [10.0.22621.2506] -> vmuidevices.dll
amd64_hyperv-vp9fs_31bf3856ad364e35 [10.0.22621.2506] -> vp9fs.dll
amd64_hyperv-vpcibus_31bf3856ad364e35 [10.0.22621.2506] -> vmvpci.dll
amd64_hyperv-winhvemulation_31bf3856ad364e35 [10.0.22621.2506] -> winhvemulation.dll
amd64_hyperv-winhvplatform_31bf3856ad364e35 [10.0.22621.2506] -> winhvplatform.dll
amd64_libarchive-internal_31bf3856ad364e35 [10.0.22621.2506] -> archiveint.dll
amd64_localuserimageprovider_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.localuserimageprovider.dll
amd64_mdmsettingsprov_31bf3856ad364e35 [10.0.22621.2506] -> mdmsettingsprov.dll
amd64_mediatransportcontrols-model_31bf3856ad364e35 [10.0.22621.2506] -> mtcmodel.dll
amd64_microsoft-client-li..e-flexible-platform_31bf3856ad364e35 [10.0.22621.2715] * -> fclip.exe
amd64_microsoft-client-li..e-licensing-service_31bf3856ad364e35 [10.0.22621.2506] -> clipdls.exe
amd64_microsoft-client-li..ing-platform-client_31bf3856ad364e35 [10.0.22621.2506] -> clipc.dll, licensingdiag.exe, oemlicense.dll
amd64_microsoft-client-li..m-service-migration_31bf3856ad364e35 [10.0.22621.2506] -> clipmigplugin.dll, clipup.exe
amd64_microsoft-client-li..platform-pkeyhelper_31bf3856ad364e35 [10.0.22621.2506] -> pkeyhelper.dll
amd64_microsoft-client-li..se-platform-service_31bf3856ad364e35 [10.0.22621.2506] -> clipsvc.dll
amd64_microsoft-client-li..sing-platform-winrt_31bf3856ad364e35 [10.0.22621.2506] -> clipwinrt.dll
amd64_microsoft-client-licensing-licensingcsp_31bf3856ad364e35 [10.0.22621.2506] -> licensingcsp.dll
amd64_microsoft-composabl..entexperiencecommon_31bf3856ad364e35 [10.0.22621.2506] -> consentexperiencecommon.dll
amd64_microsoft-composable-dragdrop_31bf3856ad364e35 [10.0.22621.2506] -> windowsinternal.composableshell.experiences.dragdrop.dll
amd64_microsoft-composable-switcher_31bf3856ad364e35 [10.0.22621.2506] -> windowsinternal.composableshell.experiences.switcher.dll
amd64_microsoft-composable-timelineui_31bf3856ad364e35 [10.0.22621.2506] -> taskflowui.dll
amd64_microsoft-edge-webview_31bf3856ad364e35 [10.0.22621.2506] -> augloop_client.dll, concrt140.dll, d3dcompiler_47.dll, dual_engine_adapter_x64.dll, dwritemin.dll, embeddedbrowserwebview.dll, eventlog_provider.dll, ffmpeg.dll, learning_tools.dll, libegl.dll, libglesv2.dll, libsmartscreenn.dll, microsoft_shell_integration.dll, mip_core.dll, mip_protection_sdk.dll, mojo_core.dll, msedge.dll, msedge_elf.dll, msedge_wer.dll, msedgewebview2.exe, mspdf.dll, msvcp140.dll, msvcp140_codecvt_ids.dll, notification_helper.exe, oneauth.dll, oneds.dll, onnxruntime.dll, onramp.dll, pdfpreviewhandler.dll, prefs_enclave_x64.dll, telclient.dll, vccorlib140.dll, vcruntime140.dll, vcruntime140_1.dll, vk_swiftshader.dll, vulkan-1.dll, wdag.dll, webview2_integration.dll, widevinecdm.dll, wns_push_client.dll
amd64_microsoft-gaming-ga..rnal-presencewriter_31bf3856ad364e35 [10.0.22621.2506] -> gamebarpresencewriter.exe, gamebarpresencewriter.proxy.dll
amd64_microsoft-hns-diagnosticstool_31bf3856ad364e35 [10.0.22621.2506] -> hnsdiag.exe
amd64_microsoft-hostguardianclient-service_31bf3856ad364e35 [10.0.22621.2506] -> hgclientservice.dll, hgclientserviceps.dll
amd64_microsoft-hyper-v-clustering-vmclusex_31bf3856ad364e35 [10.0.22621.2506] -> vmclusex.dll
amd64_microsoft-hyper-v-d..s-vmswitch-netsetup_31bf3856ad364e35 [10.0.22621.2715] * -> nvspinfo.exe, vmsproxy.sys, vmsproxyhnic.sys, vmswitch.sys
amd64_microsoft-hyper-v-drivers-hypervisor_31bf3856ad364e35 [10.0.22621.2715] * -> hvax64.exe, hvix64.exe, hvloader.dll, kdhvcom.dll
amd64_microsoft-hyper-v-hgs_31bf3856ad364e35 [10.0.22621.2506] -> vmhgs.dll
amd64_microsoft-hyper-v-i..ationcomponents-rdv_31bf3856ad364e35 [10.0.22621.2506] -> vmicrdv.dll
amd64_microsoft-hyper-v-integration-rdv-core_31bf3856ad364e35 [10.0.22621.2506] -> vmrdvcore.dll
amd64_microsoft-hyper-v-kmcl_31bf3856ad364e35 [10.0.22621.2506] -> vmbkmcl.sys
amd64_microsoft-hyper-v-kmclr_31bf3856ad364e35 [10.0.22621.2506] -> vmbkmclr.sys
amd64_microsoft-hyper-v-m..t-remotefilebrowser_31bf3856ad364e35 [10.0.22621.2506] -> remotefilebrowse.dll
amd64_microsoft-hyper-v-ram-parser_31bf3856ad364e35 [10.0.22621.2506] -> ramparser.sys
amd64_microsoft-hyper-v-sysprep-provider_31bf3856ad364e35 [10.0.22621.2506] -> hypervsysprepprovider.dll
amd64_microsoft-hyper-v-vhd-parser_31bf3856ad364e35 [10.0.22621.2506] -> vhdparser.sys
amd64_microsoft-hyper-v-vstack-config_31bf3856ad364e35 [10.0.22621.2506] -> vsconfig.dll
amd64_microsoft-hyper-v-vstack-debug_31bf3856ad364e35 [10.0.22621.2506] -> vmdebug.dll
amd64_microsoft-hyper-v-vstack-vmms_31bf3856ad364e35 [10.0.22621.2506] -> vmms.exe
amd64_microsoft-hyper-v-vstack-vmwp_31bf3856ad364e35 [10.0.22621.2506] -> vmwp.exe
amd64_microsoft-hyper-v-vstack-vsmb_31bf3856ad364e35 [10.0.22621.2506] -> vmsmb.dll, vmusrv.dll
amd64_microsoft-hyper-v-winhv_31bf3856ad364e35 [10.0.22621.2506] -> winhv.sys
amd64_microsoft-hyper-v-winhvr_31bf3856ad364e35 [10.0.22621.2715] * -> winhvr.sys
amd64_microsoft-media-cap..ternal-broadcastdvr_31bf3856ad364e35 [10.0.22621.2715] * -> bcastdvruserservice.dll
amd64_microsoft-mixedreal..assthrough.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> passthrough.exe
amd64_microsoft-onecore-a..ecore-onecore-other_31bf3856ad364e35 [10.0.22621.2506] -> midimap.dll, msacm32.drv
amd64_microsoft-onecore-a..nmodel-datatransfer_31bf3856ad364e35 [10.0.22621.2506] -> windows.applicationmodel.datatransfer.dll
amd64_microsoft-onecore-a..sibility-experience_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.accessibility.dll
amd64_microsoft-onecore-assignedaccess-csp_31bf3856ad364e35 [10.0.22621.2506] -> assignedaccesscsp.dll
amd64_microsoft-onecore-authenticationhelper_31bf3856ad364e35 [10.0.22621.2506] -> authentication.dll
amd64_microsoft-onecore-bluetooth-bthserv_31bf3856ad364e35 [10.0.22621.2506] -> bthserv.dll
amd64_microsoft-onecore-bluetooth-proxy_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.bluetooth.proxy.dll
amd64_microsoft-onecore-bluetooth-service_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.bluetooth.service.dll
amd64_microsoft-onecore-bluetooth-userapis_31bf3856ad364e35 [10.0.22621.2506] -> bluetoothapis.dll, wshbth.dll
amd64_microsoft-onecore-c..dexperiencehost-api_31bf3856ad364e35 [10.0.22621.2506] -> cloudexperiencehostcommon.dll
amd64_microsoft-onecore-c..experiencehost-user_31bf3856ad364e35 [10.0.22621.2506] -> cloudexperiencehostuser.dll
amd64_microsoft-onecore-c..ilityaccess-manager_31bf3856ad364e35 [10.0.22621.2506] -> capabilityaccessmanager.dll, capabilityaccessmanagerclient.dll
amd64_microsoft-onecore-c..lityaccess-handlers_31bf3856ad364e35 [10.0.22621.2506] -> capabilityaccesshandlers.dll
amd64_microsoft-onecore-c..ncehost-redirection_31bf3856ad364e35 [10.0.22621.2506] -> cloudexperiencehostredirection.dll
amd64_microsoft-onecore-c..ntegrity-management_31bf3856ad364e35 [10.0.22621.2506] -> manageci.dll
amd64_microsoft-onecore-c..ntux-unifiedconsent_31bf3856ad364e35 [10.0.22621.2506] -> unifiedconsent.dll
amd64_microsoft-onecore-c..periencehost-broker_31bf3856ad364e35 [10.0.22621.2506] -> cloudexperiencehostbroker.exe
amd64_microsoft-onecore-c..rivacysettingsstore_31bf3856ad364e35 [10.0.22621.2506] -> coreprivacysettingsstore.dll
amd64_microsoft-onecore-c..sbnotificationstask_31bf3856ad364e35 [10.0.22621.2506] -> usbtask.dll
amd64_microsoft-onecore-c..ss-settingshandlers_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_capabilityaccess.dll
amd64_microsoft-onecore-c..t-tokenprovidercore_31bf3856ad364e35 [10.0.22621.2506] -> microsoftaccount.tokenprovider.core.dll
amd64_microsoft-onecore-cdp-winrt_31bf3856ad364e35 [10.0.22621.2506] -> cdprt.dll
amd64_microsoft-onecore-codeintegrity-citool_31bf3856ad364e35 [10.0.22621.2506] -> citool.exe
amd64_microsoft-onecore-codeintegrity-csp_31bf3856ad364e35 [10.0.22621.2506] -> applicationcontrolcsp.dll
amd64_microsoft-onecore-codeintegrity-secure_31bf3856ad364e35 [10.0.22621.2506] -> skci.dll
amd64_microsoft-onecore-consentux-clientapi_31bf3856ad364e35 [10.0.22621.2506] -> consentuxclient.dll
amd64_microsoft-onecore-console-host-core_31bf3856ad364e35 [10.0.22621.2506] -> conhost.exe
amd64_microsoft-onecore-console-host-propsheet_31bf3856ad364e35 [10.0.22621.2506] -> console.dll
amd64_microsoft-onecore-coremessaging_31bf3856ad364e35 [10.0.22621.2506] -> coremessaging.dll
amd64_microsoft-onecore-d..ectxdatabaseupdater_31bf3856ad364e35 [10.0.22621.2506] -> directxdatabaseupdater.exe
amd64_microsoft-onecore-d..ent-dmapisetexthost_31bf3856ad364e35 [10.0.22621.2506] -> dmapisetextimpl.dll
amd64_microsoft-onecore-d..onmanager-component_31bf3856ad364e35 [10.0.22621.2506] -> dictationmanager.dll
amd64_microsoft-onecore-d..rectxdatabasehelper_31bf3856ad364e35 [10.0.22621.2506] -> directxdatabasehelper.dll
amd64_microsoft-onecore-directx-dxcore_31bf3856ad364e35 [10.0.22621.2506] -> dxcore.dll
amd64_microsoft-onecore-dusm-api_31bf3856ad364e35 [10.0.22621.2506] -> dusmapi.dll
amd64_microsoft-onecore-e..taprotectioncleanup_31bf3856ad364e35 [10.0.22621.2506] -> edpcleanup.exe, edpcsp.dll
amd64_microsoft-onecore-embeddedmodesvc_31bf3856ad364e35 [10.0.22621.2506] -> embeddedmodesvc.dll
amd64_microsoft-onecore-gameinput_31bf3856ad364e35 [10.0.22621.2506] -> gameinput.dll
amd64_microsoft-onecore-i..atedusermode-common_31bf3856ad364e35 [10.0.22621.2506] -> iumbase.dll, iumdll.dll, tprtdll.dll, ucrtbase_enclave.dll, vertdll.dll
amd64_microsoft-onecore-i..atedusermode-kernel_31bf3856ad364e35 [10.0.22621.2506] -> securekernel.exe
amd64_microsoft-onecore-i..sermode-kernel-la57_31bf3856ad364e35 [10.0.22621.2506] -> securekernella57.exe
amd64_microsoft-onecore-l..gepackmanagementcsp_31bf3856ad364e35 [10.0.22621.2506] -> languagepackmanagementcsp.dll
amd64_microsoft-onecore-l..languageoverlayutil_31bf3856ad364e35 [10.0.22621.2506] -> languageoverlayutil.dll
amd64_microsoft-onecore-l..nguageoverlayserver_31bf3856ad364e35 [10.0.22621.2506] -> languageoverlayserver.dll
amd64_microsoft-onecore-m..imedia-broadcastdvr_31bf3856ad364e35 [10.0.22621.2506] -> bcastdvr.proxy.dll, bcastdvrbroker.dll, bcastdvrclient.dll, bcastdvrcommon.dll
amd64_microsoft-onecore-m..lnamespaceextension_31bf3856ad364e35 [10.0.22621.2715] * -> dlnashext.dll
amd64_microsoft-onecore-network-qos-csp-wmi_31bf3856ad364e35 [10.0.22621.2506] -> qoswmi.dll
amd64_microsoft-onecore-networkprofile-common_31bf3856ad364e35 [10.0.22621.2506] -> netprofm.dll, npmproxy.dll
amd64_microsoft-onecore-notificationcontroller_31bf3856ad364e35 [10.0.22621.2506] -> notificationcontroller.dll, notificationcontrollerps.dll
amd64_microsoft-onecore-onlinesetup-component_31bf3856ad364e35 [10.0.22621.2506] -> oobeldr.exe, windeploy.exe
amd64_microsoft-onecore-p..evicemanagement-rtl_31bf3856ad364e35 [10.0.22621.2506] -> devobj.dll, devrtl.dll
amd64_microsoft-onecore-pickerplatform_31bf3856ad364e35 [10.0.22621.2506] -> pickerplatform.dll
amd64_microsoft-onecore-pnp-devicemanagement_31bf3856ad364e35 [10.0.22621.2506] -> cfgmgr32.dll
amd64_microsoft-onecore-pnp-drvinst_31bf3856ad364e35 [10.0.22621.2506] -> drvinst.exe
amd64_microsoft-onecore-pnp-drvsetup_31bf3856ad364e35 [10.0.22621.2506] -> 6bea57fb-8dfb-4177-9ae8-42e8b3529933_runtimedeviceinstall.dll, drvsetup.dll
amd64_microsoft-onecore-quickactions-core_31bf3856ad364e35 [10.0.22621.2506] -> quickactionsdatamodel.dll
amd64_microsoft-onecore-quiethours_31bf3856ad364e35 [10.0.22621.2506] -> quiethours.dll
amd64_microsoft-onecore-r..ping-resourcemapper_31bf3856ad364e35 [10.0.22621.2506] -> resbparser.dll, resourcemapper.dll
amd64_microsoft-onecore-s..bootencodeuefi-task_31bf3856ad364e35 [10.0.22621.2506] -> securebootencodeuefi.exe
amd64_microsoft-onecore-s..chservice-component_31bf3856ad364e35 [10.0.22621.2506] -> speechbrokeredapi.dll, speechruntime.exe, speechservicewinrtapi.proxystub.dll
amd64_microsoft-onecore-s..dlers-speechprivacy_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_speechprivacy.dll
amd64_microsoft-onecore-s..inkingtypingprivacy_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_inkingtypingprivacy.dll
amd64_microsoft-onecore-s..ngs-inputcloudstore_31bf3856ad364e35 [10.0.22621.2506] -> inputcloudstore.dll
amd64_microsoft-onecore-sharehost_31bf3856ad364e35 [10.0.22621.2506] -> sharehost.dll
amd64_microsoft-onecore-ssh-server-demand_31bf3856ad364e35 [10.0.22621.2506] -> sshsvc.dll
amd64_microsoft-onecore-sshd-pinauth_31bf3856ad364e35 [10.0.22621.2506] -> sshdbroker.dll, sshdpinauthlsa.dll
amd64_microsoft-onecore-tetheringservice_31bf3856ad364e35 [10.0.22621.2506] -> icsentitlementhost.exe, tetheringclient.dll, tetheringconfigsp.dll, tetheringservice.dll
amd64_microsoft-onecore-tiledatarepository_31bf3856ad364e35 [10.0.22621.2506] -> tiledatarepository.dll, tilestoremigrationplugin.dll
amd64_microsoft-onecore-u..latform-facilitator_31bf3856ad364e35 [10.0.22621.2506] -> facilitator.dll
amd64_microsoft-onecore-u..latform-updateagent_31bf3856ad364e35 [10.0.22621.2715] * -> updateagent.dll
amd64_microsoft-onecore-uiamanager_31bf3856ad364e35 [10.0.22621.2506] -> uiamanager.dll
amd64_microsoft-onecore-unifiedwritefilter_31bf3856ad364e35 [10.0.22621.2506] -> uwfreg.sys, uwfrtl.sys, uwfs.sys, uwfvol.sys
amd64_microsoft-onecore-utilityvm-setupagent_31bf3856ad364e35 [10.0.22621.2506] -> wcsetupagent.exe
amd64_microsoft-onecore-w..-driver-client-host_31bf3856ad364e35 [10.0.22621.2506] -> wtdhost.dll
amd64_microsoft-onecore-w..-services-commonlib_31bf3856ad364e35 [10.0.22621.2506] -> wdscommonlib.dll
amd64_microsoft-onecore-w..-threatintelligence_31bf3856ad364e35 [10.0.22621.2506] -> threatintelligence.dll
amd64_microsoft-onecore-w..atexperiencemanager_31bf3856ad364e35 [10.0.22621.2506] -> threatexperiencemanager.dll
amd64_microsoft-onecore-w..efense-user-service_31bf3856ad364e35 [10.0.22621.2506] -> webthreatdefusersvc.dll
amd64_microsoft-onecore-w..ense-secretfilterap_31bf3856ad364e35 [10.0.22621.2506] -> sfape.dll, sfapm.dll
amd64_microsoft-onecore-w..hreatdefense-driver_31bf3856ad364e35 [10.0.22621.2506] -> wtd.sys
amd64_microsoft-onecore-w..hreatresponseengine_31bf3856ad364e35 [10.0.22621.2506] -> threatresponseengine.dll
amd64_microsoft-onecore-w..reatdefense-service_31bf3856ad364e35 [10.0.22621.2506] -> webthreatdefsvc.dll
amd64_microsoft-onecore-w..river-client-sensor_31bf3856ad364e35 [10.0.22621.2506] -> wtdsensor.dll
amd64_microsoft-onecore-w..se-clipboardmonitor_31bf3856ad364e35 [10.0.22621.2506] -> wtdccm.dll
amd64_microsoft-onecore-w..se-threatassessment_31bf3856ad364e35 [10.0.22621.2506] -> threatassessment.dll
amd64_microsoft-onecore-windowmanagement_31bf3856ad364e35 [10.0.22621.2506] -> windowmanagement.dll
amd64_microsoft-onecore-windowmanagementapi_31bf3856ad364e35 [10.0.22621.2506] -> windowmanagementapi.dll
amd64_microsoft-onecore-xamltilerender_31bf3856ad364e35 [10.0.22621.2506] -> xamltilerender.dll
amd64_microsoft-onecoreua..tringfeedbackengine_31bf3856ad364e35 [10.0.22621.2506] -> stringfeedbackengine.dll
amd64_microsoft-onecoreua..uetooth-userservice_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.bluetooth.userservice.dll
amd64_microsoft-onecoreuap-deviceaccess_31bf3856ad364e35 [10.0.22621.2506] -> deviceaccess.dll
amd64_microsoft-ppiprojection.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> receiver.exe
amd64_microsoft-system-user-component_31bf3856ad364e35 [10.0.22621.2506] -> usermgrproxy.dll
amd64_microsoft-system-user-service_31bf3856ad364e35 [10.0.22621.2715] * -> usermgr.dll
amd64_microsoft-textinput-helpers_31bf3856ad364e35 [10.0.22621.2506] -> ime_textinputhelpers.dll
amd64_microsoft-ui-xaml-cbs_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.ui.xaml.dll
amd64_microsoft-webdriver-server-components_31bf3856ad364e35 [10.0.22621.2506] -> microsoftwebdriver.exe
amd64_microsoft-windows-3daudio-hrtfapo_31bf3856ad364e35 [10.0.22621.2506] -> hrtfapo.dll, hrtfdspcpu.dll, ssdm.dll, virtualsurroundapo.dll
amd64_microsoft-windows-a..-experience-apphelp_31bf3856ad364e35 [10.0.22621.2506] -> apphlpdm.dll, pcaui.exe
amd64_microsoft-windows-a..-hologramcompositor_31bf3856ad364e35 [10.0.22621.2506] -> hologramcompositor.dll
amd64_microsoft-windows-a..-messagingdatamodel_31bf3856ad364e35 [10.0.22621.2506] -> messagingdatamodel2.dll
amd64_microsoft-windows-a..-service.deployment_31bf3856ad364e35 [10.0.22621.2506] -> appreadiness.dll
amd64_microsoft-windows-a..adjustment.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> components.dll, desktoplearning.components.dll, models.dll, roomadjustment.components.dll, roomadjustmentapp.exe
amd64_microsoft-windows-a..anagement-migration_31bf3856ad364e35 [10.0.22621.2506] -> appmanmigrationplugin.dll
amd64_microsoft-windows-a..appvprogrammability_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.appv.appvclientcomconsumer.dll, microsoft.appv.appvclientpowershell.dll, microsoft.appv.appvclientwmi.dll, microsoft.appv.clientprogrammability.eventing.dll
amd64_microsoft-windows-a..atibility-assistant_31bf3856ad364e35 [10.0.22621.2506] -> pcadm.dll, pcaevts.dll, pcalua.exe, pcasvc.dll
amd64_microsoft-windows-a..bility-assistant-ui_31bf3856ad364e35 [10.0.22621.2506] -> pcacli.dll, pcaui.dll
amd64_microsoft-windows-a..bility-ui-recording_31bf3856ad364e35 [10.0.22621.2506] -> uireng.dll
amd64_microsoft-windows-a..cationmodel-daxexec_31bf3856ad364e35 [10.0.22621.2506] -> daxexec.dll
amd64_microsoft-windows-a..dcredentialprovider_31bf3856ad364e35 [10.0.22621.2506] -> smartcardcredentialprovider.dll
amd64_microsoft-windows-a..dholographicdisplay_31bf3856ad364e35 [10.0.22621.2506] -> dholographicdisplay.dll
amd64_microsoft-windows-a..e-inventory-service_31bf3856ad364e35 [10.0.22621.2506] -> inventorysvc.dll
amd64_microsoft-windows-a..eapplifetimemanager_31bf3856ad364e35 [10.0.22621.2506] -> remoteapplifetimemanager.exe, remoteapplifetimemanagerproxystub.dll
amd64_microsoft-windows-a..edaccess-shellproxy_31bf3856ad364e35 [10.0.22621.2506] -> assignedaccessshellproxy.dll
amd64_microsoft-windows-a..ema-containerosplus_31bf3856ad364e35 [10.0.22621.2506] -> apisetschema.dll
amd64_microsoft-windows-a..ence-infrastructure_31bf3856ad364e35 [10.0.22621.2506] -> apphelp.dll, sdbinst.exe, shimeng.dll
amd64_microsoft-windows-a..ence-inventory-core_31bf3856ad364e35 [10.0.22621.2506] -> aepic.dll
amd64_microsoft-windows-a..ence-mitigations-c1_31bf3856ad364e35 [10.0.22621.2506] -> acres.dll
amd64_microsoft-windows-a..ence-mitigations-c3_31bf3856ad364e35 [10.0.22621.2506] -> acgenral.dll
amd64_microsoft-windows-a..ence-mitigations-c5_31bf3856ad364e35 [10.0.22621.2506] -> aclayers.dll, acxtrnal.dll
amd64_microsoft-windows-a..entory-data-sources_31bf3856ad364e35 [10.0.22621.2506] -> devinv.dll
amd64_microsoft-windows-a..erience-apisampling_31bf3856ad364e35 [10.0.22621.2506] -> apisampling.dll
amd64_microsoft-windows-a..erience-mare-backup_31bf3856ad364e35 [10.0.22621.2506] -> aemarebackup.dll
amd64_microsoft-windows-a..esslockapp.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> assignedaccesslockapp.exe
amd64_microsoft-windows-a..etedfeaturedatabase_31bf3856ad364e35 [10.0.22621.2506] -> applicationtargetedfeaturedatabase.dll
amd64_microsoft-windows-a..extservice.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.asynctextservice.exe
amd64_microsoft-windows-a..g-whatsnew.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> analog.console.client.dll, analog.shell.util.dll, components.dll, models.dll, whatsnew.dll, whatsnewapp.exe
amd64_microsoft-windows-a..holocamera.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> analog.console.client.dll, analog.shell.util.dll, components.dll, holocamera.dll, holocameraapp.exe, mixedrealitycapture.pipeline.dll, models.dll
amd64_microsoft-windows-a..ilot-reset-credprov_31bf3856ad364e35 [10.0.22621.2506] -> mgmtrefreshcredprov.dll
amd64_microsoft-windows-a..installagent-binary_31bf3856ad364e35 [10.0.22621.2506] -> rdsappxhelper.dll
amd64_microsoft-windows-a..iocorepolicymanager_31bf3856ad364e35 [10.0.22621.2506] -> audiosrvpolicymanager.dll
amd64_microsoft-windows-a..ionmodel-lockscreen_31bf3856ad364e35 [10.0.22621.2506] -> windows.applicationmodel.lockscreen.dll
amd64_microsoft-windows-a..itemplayer.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> components.dll, holoitemplayer.dll, holoitemplayerapp.exe, models.dll
amd64_microsoft-windows-a..l-appexecutionalias_31bf3856ad364e35 [10.0.22621.2506] -> apisethost.appexecutionalias.dll
amd64_microsoft-windows-a..lity-braille-brlapi_31bf3856ad364e35 [10.0.22621.2506] -> brlapi.dll
amd64_microsoft-windows-a..lity-braille-brltty_31bf3856ad364e35 [10.0.22621.2506] -> brlapi-0.8.dll, brltty.exe, libgcc_s_dw2-1.dll, libiconv-2.dll, libpdcurses.dll, libpdcursesu.dll, libpdcursesw.dll, libusb-1.0.dll
amd64_microsoft-windows-a..lity-eoaexperiences_31bf3856ad364e35 [10.0.22621.2506] -> eoaexperiences.exe
amd64_microsoft-windows-a..modernappmanagement_31bf3856ad364e35 [10.0.22621.2506] -> enterprisemodernappmgmtcsp.dll
amd64_microsoft-windows-a..n-experience-appinv_31bf3856ad364e35 [10.0.22621.2506] -> aeinv.dll
amd64_microsoft-windows-a..nagement-appvclient_31bf3856ad364e35 [10.0.22621.2506] -> appvcatalog.dll, appventstreamingmanager.dll, appventsubsystemcontroller.dll, appventvirtualization.dll, appvetwclientres.dll, appvetwstreamingux.dll, appvfilesystemmetadata.dll, appvintegration.dll, appvmanifest.dll, appvnice.exe, appvorchestration.dll, appvpolicy.dll, appvpublishing.dll, appvreporting.dll, appvscripting.dll, appvshnotify.exe, appvstreamingux.dll, appvstreamingux.exe, appvstreammap.dll, scriptrunner.exe, syncappvpublishingserver.exe, transportdsa.dll
amd64_microsoft-windows-a..nagement-appvsystem_31bf3856ad364e35 [10.0.22621.2506] -> appvclient.exe, appvstrm.sys, appvvemgr.sys, appvvfs.sys
amd64_microsoft-windows-a..nagement-uevservice_31bf3856ad364e35 [10.0.22621.2506] -> agentservice.exe, microsoft.uev.agentdriverevents.dll, uevagentdriver.sys
amd64_microsoft-windows-a..nager-runtimeserver_31bf3856ad364e35 [10.0.22621.2506] -> assignedaccessmanager.dll, assignedaccessmanagersvc.dll
amd64_microsoft-windows-a..ncredentialprovider_31bf3856ad364e35 [10.0.22621.2506] -> facecredentialprovider.dll
amd64_microsoft-windows-a..ntscontrol.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> accountscontrolhost.exe, accountscontrolui.dll
amd64_microsoft-windows-a..o-mmecore-winmmbase_31bf3856ad364e35 [10.0.22621.2506] -> winmm.dll
amd64_microsoft-windows-a..on-authui-component_31bf3856ad364e35 [10.0.22621.2506] -> authui.dll
amd64_microsoft-windows-a..on-experience-tools_31bf3856ad364e35 [10.0.22621.2506] -> acppage.dll
amd64_microsoft-windows-a..one-updater-service_31bf3856ad364e35 [10.0.22621.2506] -> tzautoupdate.dll
amd64_microsoft-windows-a..oplearning.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> desktoplearningapp.exe
amd64_microsoft-windows-a..perience-ait-static_31bf3856ad364e35 [10.0.22621.2506] -> aitstatic.exe
amd64_microsoft-windows-a..rarydialog.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> addsuggestedfolderstolibrarydialog.exe
amd64_microsoft-windows-a..recognitionadapters_31bf3856ad364e35 [10.0.22621.2506] -> facebootstrapadapter.dll
amd64_microsoft-windows-a..rience-program-data_31bf3856ad364e35 [10.0.22621.2506] -> invagent.dll, win32appinventorycsp.dll
amd64_microsoft-windows-a..roblemstepsrecorder_31bf3856ad364e35 [10.0.22621.2506] -> psr.exe
amd64_microsoft-windows-a..toplearninghydrogen_31bf3856ad364e35 [10.0.22621.2506] -> analog.shell.util.dll, components.dll, desktoplearning.components.dll, desktoplearning.models.dll, models.dll, roomadjustment.components.dll
amd64_microsoft-windows-a..ty-braille-liblouis_31bf3856ad364e35 [10.0.22621.2506] -> liblouis.dll
amd64_microsoft-windows-a..y-delegation-wizard_31bf3856ad364e35 [10.0.22621.2506] -> dsuiwiz.dll
amd64_microsoft-windows-aarsvc_31bf3856ad364e35 [10.0.22621.2506] -> aarsvc.dll, agentactivationruntime.dll, agentactivationruntimestarter.exe, agentactivationruntimewindows.dll, windows.applicationmodel.conversationalagent.dll, windows.applicationmodel.conversationalagent.internal.proxystub.dll, windows.applicationmodel.conversationalagent.proxystub.dll
amd64_microsoft-windows-accessibilitycpl_31bf3856ad364e35 [10.0.22621.2506] -> accessibilitycpl.dll
amd64_microsoft-windows-accountscontrol-api_31bf3856ad364e35 [10.0.22621.2506] -> windows.accountscontrol.dll
amd64_microsoft-windows-aclui_31bf3856ad364e35 [10.0.22621.2506] -> aclui.dll
amd64_microsoft-windows-acpiex_31bf3856ad364e35 [10.0.22621.2506] -> acpiex.sys
amd64_microsoft-windows-activationmanager_31bf3856ad364e35 [10.0.22621.2506] -> activationmanager.dll
amd64_microsoft-windows-activexproxy_31bf3856ad364e35 [10.0.22621.2506] -> actxprxy.dll
amd64_microsoft-windows-acx-classextension_31bf3856ad364e35 [10.0.22621.2506] -> acx01000.sys
amd64_microsoft-windows-ad-propertypages_31bf3856ad364e35 [10.0.22621.2506] -> adprop.dll
amd64_microsoft-windows-advancedtaskmanager_31bf3856ad364e35 [10.0.22621.2506] -> launchtm.exe, taskmanagerdatalayer.dll, taskmgr.exe
amd64_microsoft-windows-advapi32_31bf3856ad364e35 [10.0.22621.2715] * -> advapi32.dll
amd64_microsoft-windows-ahcache_31bf3856ad364e35 [10.0.22621.2506] -> ahcache.sys
amd64_microsoft-windows-alljoyn-api_31bf3856ad364e35 [10.0.22621.2506] -> msajapi.dll
amd64_microsoft-windows-analog-facefodhandler_31bf3856ad364e35 [10.0.22621.2506] -> facefoduninstaller.exe
amd64_microsoft-windows-apisetschema-windows_31bf3856ad364e35 [10.0.22621.2506] -> apisetschema.dll
amd64_microsoft-windows-appcontract-bmpolicy_31bf3856ad364e35 [10.0.22621.2506] -> acpbackgroundmanagerpolicy.dll
amd64_microsoft-windows-appdefaults_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.appdefaults.dll
amd64_microsoft-windows-appid_31bf3856ad364e35 [10.0.22621.2506] -> appidapi.dll, appidcertstorecheck.exe, appidpolicyconverter.exe, appidsvc.dll
amd64_microsoft-windows-appidcore_31bf3856ad364e35 [10.0.22621.2506] -> appid.sys, appidtel.exe, applockercsp.dll, applockerfltr.sys, srpapi.dll
amd64_microsoft-windows-applistbackuplauncher_31bf3856ad364e35 [10.0.22621.2506] -> applistbackuplauncher.dll
amd64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35 [10.0.22621.2506] -> appvclientps.dll, appvdllsurrogate.exe, appventsubsystems64.dll, appvsentinel.dll, appvterminator.dll, mavinject.exe
amd64_microsoft-windows-appmanagement-uevagent_31bf3856ad364e35 [10.0.22621.2506] -> applysettingstemplatecatalog.exe, microsoft.uev.cabutil.dll, microsoft.uev.cmutil.dll, microsoft.uev.common.dll, microsoft.uev.common.winrt.dll, microsoft.uev.commonbridge.dll, microsoft.uev.configwrapper.dll, microsoft.uev.cscunpintool.exe, microsoft.uev.eventlogmessages.dll, microsoft.uev.localsyncprovider.dll, microsoft.uev.managedeventlogging.dll, microsoft.uev.management.dll, microsoft.uev.management.wmiaccess.dll, microsoft.uev.modernappagent.dll, microsoft.uev.modernappcore.dll, microsoft.uev.modernappdata.winrt.dll, microsoft.uev.modernsync.dll, microsoft.uev.monitorsyncprovider.dll, microsoft.uev.printercustomactions.dll, microsoft.uev.smbsyncprovider.dll, microsoft.uev.synccommon.dll, microsoft.uev.syncconditions.dll, microsoft.uev.synccontroller.exe, uevagentpolicygenerator.exe, uevappmonitor.exe, uevtemplatebaselinegenerator.exe, uevtemplateconfigitemgenerator.exe
amd64_microsoft-windows-appmanagement-uevpsmof_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.uev.agentwmi.dll, microsoft.uev.commands.dll
amd64_microsoft-windows-appmanagement-uevwow_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.uev.appagent.dll, microsoft.uev.office2010customactions.dll, microsoft.uev.office2013customactions.dll
amd64_microsoft-windows-appraiser-media-base_31bf3856ad364e35 [10.0.22621.2506] -> appraiser.dll
amd64_microsoft-windows-apprep-chxapp.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> chxsmartscreen.exe
amd64_microsoft-windows-appresolver_31bf3856ad364e35 [10.0.22621.2506] -> appresolver.dll
amd64_microsoft-windows-appresolverux.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> appresolverux.exe
amd64_microsoft-windows-appwiz_31bf3856ad364e35 [10.0.22621.2506] -> appwiz.cpl
amd64_microsoft-windows-appx-alluserstore_31bf3856ad364e35 [10.0.22621.2506] -> appxalluserstore.dll
amd64_microsoft-windows-appx-deployment-client_31bf3856ad364e35 [10.0.22621.2506] -> appxdeploymentclient.dll
amd64_microsoft-windows-appx-deployment-server_31bf3856ad364e35 [10.0.22621.2715] * -> appinstallerbackgroundupdate.exe, applytrustoffline.exe, appxapplicabilityblob.dll, appxdeploymentextensions.desktop.dll, appxdeploymentextensions.onecore.dll, appxdeploymentserver.dll, appxupgrademigrationplugin.dll, custominstallexec.exe
amd64_microsoft-windows-appx-sysprep_31bf3856ad364e35 [10.0.22621.2506] -> appxsysprep.dll
amd64_microsoft-windows-appxsip_31bf3856ad364e35 [10.0.22621.2506] -> appxsip.dll
amd64_microsoft-windows-apx-proxyextension_31bf3856ad364e35 [10.0.22621.2506] -> apx01000.dll
amd64_microsoft-windows-assignedaccess-guard_31bf3856ad364e35 [10.0.22621.2506] -> assignedaccessguard.exe
amd64_microsoft-windows-at_31bf3856ad364e35 [10.0.22621.2506] -> at.exe
amd64_microsoft-windows-atbroker_31bf3856ad364e35 [10.0.22621.2506] -> atbroker.exe
amd64_microsoft-windows-attest-client_31bf3856ad364e35 [10.0.22621.2506] -> azureattest.dll, azureattestmanager.dll, azureattestnormal.dll
amd64_microsoft-windows-audio-audiocore-client_31bf3856ad364e35 [10.0.22621.2506] -> audioses.dll
amd64_microsoft-windows-audio-audiocore_31bf3856ad364e35 [10.0.22621.2506] -> audiodg.exe, audioendpointbuilder.dll, audioeng.dll, audiokse.dll, audioresourceregistrar.dll, audiosrv.dll, coremas.dll, remoteaudioendpoint.dll, spatialaudiolicensesrv.exe
amd64_microsoft-windows-audio-dmusic_31bf3856ad364e35 [10.0.22621.2506] -> dmloader.dll, dmsynth.dll, dmusic.dll, dswave.dll
amd64_microsoft-windows-audio-dsound_31bf3856ad364e35 [10.0.22621.2506] -> dsdmo.dll, dsound.dll
amd64_microsoft-windows-audio-spatializer_31bf3856ad364e35 [10.0.22621.2506] -> spatializerapo.dll
amd64_microsoft-windows-audio-vac-service_31bf3856ad364e35 [10.0.22621.2506] -> vac.dll
amd64_microsoft-windows-audio-volumecontrol_31bf3856ad364e35 [10.0.22621.2506] -> sndvol.exe, sndvolsso.dll
amd64_microsoft-windows-authext_31bf3856ad364e35 [10.0.22621.2506] -> authext.dll
amd64_microsoft-windows-autochk_31bf3856ad364e35 [10.0.22621.2506] -> autochk.exe
amd64_microsoft-windows-axinstallservice_31bf3856ad364e35 [10.0.22621.2506] -> axinstsv.dll, axinstui.exe
amd64_microsoft-windows-b..-configuration-data_31bf3856ad364e35 [10.0.22621.2506] -> bcd.dll
amd64_microsoft-windows-b..ertransport-network_31bf3856ad364e35 [10.0.22621.2506] -> kd_02_10df.dll, kd_02_10ec.dll, kd_02_1137.dll, kd_02_14e4.dll, kd_02_15b3.dll, kd_02_1969.dll, kd_02_19a2.dll, kd_02_1af4.dll, kd_02_8086.dll, kd_07_1415.dll, kd_0c_8086.dll, kdnet_uart16550.dll
amd64_microsoft-windows-b..ggertransport-kdnet_31bf3856ad364e35 [10.0.22621.2506] -> kdnet.dll, kdstub.dll
amd64_microsoft-windows-b..infrastructurewinrt_31bf3856ad364e35 [10.0.22621.2506] -> biwinrt.dll
amd64_microsoft-windows-b..iondata-cmdlinetool_31bf3856ad364e35 [10.0.22621.2506] -> bcdedit.exe
amd64_microsoft-windows-b..notificationmanager_31bf3856ad364e35 [10.0.22621.2506] -> bnmanager.dll
amd64_microsoft-windows-b..onment-core-tcbboot_31bf3856ad364e35 [10.0.22621.2715] * -> tcblaunch.exe, tcbloader.dll
amd64_microsoft-windows-b..ux-winre.deployment_31bf3856ad364e35 [10.0.22621.2506] -> bootux.dll
amd64_microsoft-windows-b..vironment-os-loader_31bf3856ad364e35 [10.0.22621.2506] -> winload.exe
amd64_microsoft-windows-b..vironment-os-resume_31bf3856ad364e35 [10.0.22621.2506] -> winresume.exe
amd64_microsoft-windows-b..vironment-servicing_31bf3856ad364e35 [10.0.22621.2506] -> bfsvc.exe, bootsvc.dll
amd64_microsoft-windows-basic-misc-tools_31bf3856ad364e35 [10.0.22621.2506] -> netmsg.dll
amd64_microsoft-windows-batmeter_31bf3856ad364e35 [10.0.22621.2506] -> batmeter.dll
amd64_microsoft-windows-bcdboot-cmdlinetool_31bf3856ad364e35 [10.0.22621.2506] -> bcdboot.exe
amd64_microsoft-windows-bcp47languages_31bf3856ad364e35 [10.0.22621.2506] -> bcp47langs.dll, bcp47mrm.dll
amd64_microsoft-windows-bcrypt-dll_31bf3856ad364e35 [10.0.22621.2506] -> bcrypt.dll
amd64_microsoft-windows-bcrypt-primitives-dll_31bf3856ad364e35 [10.0.22621.2506] -> bcryptprimitives.dll
amd64_microsoft-windows-bind-filter_31bf3856ad364e35 [10.0.22621.2506] -> bindflt.sys, bindfltapi.dll
amd64_microsoft-windows-bioenrollment.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> bioenrollmenthost.exe, bioenrollmentui.dll
amd64_microsoft-windows-bits-client-core_31bf3856ad364e35 [10.0.22621.2506] -> qmgr.dll
amd64_microsoft-windows-bitsdiagnostic_31bf3856ad364e35 [10.0.22621.2506] -> diagpackage.dll
amd64_microsoft-windows-bootmenuux_31bf3856ad364e35 [10.0.22621.2506] -> bootmenuux.dll
amd64_microsoft-windows-bootux.deployment_31bf3856ad364e35 [10.0.22621.2506] -> bootim.exe, bootux.dll
amd64_microsoft-windows-branding-engine_31bf3856ad364e35 [10.0.22621.2506] -> winbrand.dll, winsku.dll
amd64_microsoft-windows-brokerinfrastructure_31bf3856ad364e35 [10.0.22621.2506] -> bisrv.dll
amd64_microsoft-windows-browser-brokers_31bf3856ad364e35 [11.0.22621.2506] -> browser_broker.exe, browserbroker.dll, browserexport.exe
amd64_microsoft-windows-browserservice-netapi_31bf3856ad364e35 [10.0.22621.2506] -> browcli.dll
amd64_microsoft-windows-browserservice_31bf3856ad364e35 [10.0.22621.2506] -> browser.dll
amd64_microsoft-windows-bth-cpl_31bf3856ad364e35 [10.0.22621.2506] -> bthprops.cpl
amd64_microsoft-windows-bth-user_31bf3856ad364e35 [10.0.22621.2506] -> bluetoothopppushclient.dll, bthudtask.exe, fsquirt.exe
amd64_microsoft-windows-c..-disposableclientvm_31bf3856ad364e35 [10.0.22621.2506] -> madrid.dll, windowssandbox.exe, windowssandboxclient.exe
amd64_microsoft-windows-c..-joinprovideronline_31bf3856ad364e35 [10.0.22621.2506] -> joinproviderol.dll
amd64_microsoft-windows-c..-radiomediaprovider_31bf3856ad364e35 [10.0.22621.2506] -> bthradiomedia.dll
amd64_microsoft-windows-c..alenrollmentmanager_31bf3856ad364e35 [10.0.22621.2506] -> credentialenrollmentmanager.exe, credentialenrollmentmanagerforuser.dll
amd64_microsoft-windows-c..alproviders-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovs.dll
amd64_microsoft-windows-c..ana-constraintindex_31bf3856ad364e35 [10.0.22621.2506] -> constraintindex.search.dll
amd64_microsoft-windows-c..atemanagersnapindll_31bf3856ad364e35 [10.0.22621.2506] -> certmgr.dll
amd64_microsoft-windows-c..bluetooth-telemetry_31bf3856ad364e35 [10.0.22621.2506] -> bthtelemetry.dll
amd64_microsoft-windows-c..brokeredapi-desktop_31bf3856ad364e35 [10.0.22621.2506] -> windows.cortana.desktop.dll
amd64_microsoft-windows-c..brokeredapi-onecore_31bf3856ad364e35 [10.0.22621.2506] -> windows.cortana.onecore.dll
amd64_microsoft-windows-c..cn-config-registrar_31bf3856ad364e35 [10.0.22621.2506] -> wcnapi.dll, wcncsvc.dll, wcneapauthproxy.dll, wcneappeerproxy.dll
amd64_microsoft-windows-c..complus-eventsystem_31bf3856ad364e35 [10.0.22621.2506] -> es.dll
amd64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35 [10.0.22621.2506] -> catsrv.dll, clbcatq.dll, colbact.dll
amd64_microsoft-windows-c..dialoghost.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> creddialoghost.exe
amd64_microsoft-windows-c..dstore-schema-shell_31bf3856ad364e35 [10.0.22621.2506] -> windows.cloudstore.schema.shell.dll
amd64_microsoft-windows-c..dtc-runtime-cluster_31bf3856ad364e35 [10.0.22621.2506] -> mtxclu.dll
amd64_microsoft-windows-c..ent-appxpackagingom_31bf3856ad364e35 [10.0.22621.2506] -> appxpackaging.dll
amd64_microsoft-windows-c..ent-indexing-common_31bf3856ad364e35 [10.0.22621.2506] -> query.dll
amd64_microsoft-windows-c..ers-storage-library_31bf3856ad364e35 [10.0.22621.2506] -> wc_storage.dll
amd64_microsoft-windows-c..ervices-ca-certpdef_31bf3856ad364e35 [10.0.22621.2506] -> certpdef.dll
amd64_microsoft-windows-c..ervices-certadm-dll_31bf3856ad364e35 [10.0.22621.2506] -> certadm.dll
amd64_microsoft-windows-c..erymanager.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> contentdeliverymanager.background.dll, contentmanagementsdk.dll
amd64_microsoft-windows-c..esources-deployment_31bf3856ad364e35 [10.0.22621.2506] -> mrmdeploy.dll
amd64_microsoft-windows-c..esources-mrmindexer_31bf3856ad364e35 [10.0.22621.2506] -> mrmindexer.dll
amd64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35 [10.0.22621.2506] -> catsrvut.dll, comsvcs.dll
amd64_microsoft-windows-c..gureexpandedstorage_31bf3856ad364e35 [10.0.22621.2506] -> configureexpandedstorage.dll
amd64_microsoft-windows-c..hell-desktophosting_31bf3856ad364e35 [10.0.22621.2506] -> windowsinternal.composableshell.desktophosting.dll
amd64_microsoft-windows-c..iderslegacy-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovslegacy.dll
amd64_microsoft-windows-c..inventory-nonarpinv_31bf3856ad364e35 [10.0.22621.2506] -> nonarpinv.dll
amd64_microsoft-windows-c..m-initmachineconfig_31bf3856ad364e35 [10.0.22621.2506] -> cmimcext.sys
amd64_microsoft-windows-c..ngshellapp.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> callingshellapp.exe, callingshellapppresenters.dll, windowsinternal.shell.experiences.callingshellappcontrols.dll
amd64_microsoft-windows-c..ntegrity-aggregator_31bf3856ad364e35 [10.0.22621.2506] -> codeintegrityaggregator.dll
amd64_microsoft-windows-c..ocspadminnative-dll_31bf3856ad364e35 [10.0.22621.2506] -> ocspadminnative.dll
amd64_microsoft-windows-c..olation-file-system_31bf3856ad364e35 [10.0.22621.2506] -> wci.dll, wcifs.sys
amd64_microsoft-windows-c..onentpackagesupport_31bf3856ad364e35 [10.0.22621.2506] -> comppkgsrv.exe, comppkgsup.dll
amd64_microsoft-windows-c..op-transitionscreen_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.shell.clouddesktop.transitionscreen.dll
amd64_microsoft-windows-c..ore-earlydownloader_31bf3856ad364e35 [10.0.22621.2506] -> windows.cloudstore.earlydownloader.dll
amd64_microsoft-windows-c..ov2fahelper-library_31bf3856ad364e35 [10.0.22621.2506] -> credprov2fahelper.dll
amd64_microsoft-windows-c..ovdatamodel-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovdatamodel.dll
amd64_microsoft-windows-c..pc-settingshandlers_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_cloudpc.dll
amd64_microsoft-windows-c..provision-framework_31bf3856ad364e35 [10.0.22621.2506] -> netprovfw.dll
amd64_microsoft-windows-c..rformance-xperfcore_31bf3856ad364e35 [10.0.22621.2506] -> diagperf.dll
amd64_microsoft-windows-c..riencehost.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.cloudexperiencehost.dll, microsoftaccount.tokenprovider.dll
amd64_microsoft-windows-c..rymanager-utilities_31bf3856ad364e35 [10.0.22621.2715] * -> contentdeliverymanager.utilities.dll
amd64_microsoft-windows-c..schema-desktopshell_31bf3856ad364e35 [10.0.22621.2506] -> windows.cloudstore.schema.desktopshell.dll
amd64_microsoft-windows-c..serframework-legacy_31bf3856ad364e35 [10.0.22621.2506] -> composerframework.dll
amd64_microsoft-windows-c..services-certca-dll_31bf3856ad364e35 [10.0.22621.2506] -> certca.dll
amd64_microsoft-windows-c..t-resources-mrmcore_31bf3856ad364e35 [10.0.22621.2506] -> mrmcorer.dll
amd64_microsoft-windows-c..t-xpsomandstreaming_31bf3856ad364e35 [10.0.22621.2506] -> xpspushlayer.dll, xpsservices.dll
amd64_microsoft-windows-c..tem-tracedatahelper_31bf3856ad364e35 [10.0.22621.2506] -> tdh.dll
amd64_microsoft-windows-c..tionauthorityclient_31bf3856ad364e35 [10.0.22621.2506] -> certcli.dll
amd64_microsoft-windows-c..top-clouddesktopcsp_31bf3856ad364e35 [10.0.22621.2506] -> clouddesktopcsp.dll
amd64_microsoft-windows-c..tprovision-joinutil_31bf3856ad364e35 [10.0.22621.2506] -> joinutil.dll
amd64_microsoft-windows-c..uetooth-dafprovider_31bf3856ad364e35 [10.0.22621.2506] -> dafbth.dll
amd64_microsoft-windows-c..urces-applicability_31bf3856ad364e35 [10.0.22621.2506] -> appxapplicabilityengine.dll
amd64_microsoft-windows-c..utermanagerlauncher_31bf3856ad364e35 [10.0.22621.2506] -> compmgmtlauncher.exe
amd64_microsoft-windows-c..xperiencehostbroker_31bf3856ad364e35 [10.0.22621.2506] -> cloudexperiencehostbroker.dll
amd64_microsoft-windows-cabinet_31bf3856ad364e35 [10.0.22621.2506] -> cabinet.dll
amd64_microsoft-windows-cabview_31bf3856ad364e35 [10.0.22621.2506] -> cabview.dll
amd64_microsoft-windows-capturepicker.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> capturepicker.exe
amd64_microsoft-windows-captureservice_31bf3856ad364e35 [10.0.22621.2506] -> captureservice.dll
amd64_microsoft-windows-cdfs_31bf3856ad364e35 [10.0.22621.2506] -> cdfs.sys
amd64_microsoft-windows-cdp-api_31bf3856ad364e35 [10.0.22621.2506] -> cdp.dll
amd64_microsoft-windows-cdpsvc_31bf3856ad364e35 [10.0.22621.2506] -> cdpsvc.dll
amd64_microsoft-windows-cdpusersvc_31bf3856ad364e35 [10.0.22621.2506] -> cdpusersvc.dll
amd64_microsoft-windows-certificaterequesttool_31bf3856ad364e35 [10.0.22621.2506] -> certreq.exe
amd64_microsoft-windows-certutil_31bf3856ad364e35 [10.0.22621.2506] -> certenc.dll, certutil.exe
amd64_microsoft-windows-chsime-binaries_31bf3856ad364e35 [10.0.22621.2506] -> chsadvancedds.dll, chsem.dll, chslexiconupdateds.dll, chspinyinds.dll, chsproxyds.dll, chswubids.dll, serviceds.dll
amd64_microsoft-windows-chsime-wubi_31bf3856ad364e35 [10.0.22621.2506] -> chswubids.dll
amd64_microsoft-windows-ci-wldp-dll_31bf3856ad364e35 [10.0.22621.2506] -> wldp.dll
amd64_microsoft-windows-classpnp-minwin_31bf3856ad364e35 [10.0.22621.2506] -> classpnp.sys
amd64_microsoft-windows-clipboard-userservice_31bf3856ad364e35 [10.0.22621.2506] -> cbdhsvc.dll
amd64_microsoft-windows-clouddomainjoinaug_31bf3856ad364e35 [10.0.22621.2506] -> clouddomainjoinaug.dll
amd64_microsoft-windows-cloudexperiencehostapi_31bf3856ad364e35 [10.0.22621.2506] -> cloudexperiencehost.dll
amd64_microsoft-windows-cloudfiles-apilibrary_31bf3856ad364e35 [10.0.22621.2506] -> cldapi.dll
amd64_microsoft-windows-cloudfiles-filter_31bf3856ad364e35 [10.0.22621.2715] * -> cldflt.sys
amd64_microsoft-windows-cloudnotifications_31bf3856ad364e35 [10.0.22621.2506] -> cloudnotifications.exe
amd64_microsoft-windows-cloudrestorelauncher_31bf3856ad364e35 [10.0.22621.2506] -> cloudrestorelauncher.dll
amd64_microsoft-windows-cloudstore_31bf3856ad364e35 [10.0.22621.2506] -> windows.cloudstore.dll
amd64_microsoft-windows-cmisetup_31bf3856ad364e35 [10.0.22621.2506] -> cmisetup.dll
amd64_microsoft-windows-cng_31bf3856ad364e35 [10.0.22621.2506] -> cng.sys
amd64_microsoft-windows-codeintegrity_31bf3856ad364e35 [10.0.22621.2506] -> ci.dll
amd64_microsoft-windows-com-base-qfe-ole32_31bf3856ad364e35 [10.0.22621.2506] -> ole32.dll
amd64_microsoft-windows-com-base-qfe-rpcss_31bf3856ad364e35 [10.0.22621.2506] -> rpcss.dll
amd64_microsoft-windows-com-base_31bf3856ad364e35 [10.0.22621.2506] -> combase.dll, wincorlib.dll, wintypes.dll
amd64_microsoft-windows-com-coml2_31bf3856ad364e35 [10.0.22621.2506] -> coml2.dll
amd64_microsoft-windows-com-dtc-client_31bf3856ad364e35 [10.0.22621.2506] -> msdtcprx.dll, msdtcspoffln.dll, xolehlp.dll
amd64_microsoft-windows-com-dtc-management-ui_31bf3856ad364e35 [10.0.22621.2506] -> msdtcuiu.dll
amd64_microsoft-windows-com-dtc-management-wmi_31bf3856ad364e35 [10.0.22621.2506] -> msdtcwmi.dll
amd64_microsoft-windows-com-dtc-oraclesupport_31bf3856ad364e35 [10.0.22621.2506] -> mtxoci.dll
amd64_microsoft-windows-com-dtc-runtime-log_31bf3856ad364e35 [10.0.22621.2506] -> msdtclog.dll
amd64_microsoft-windows-com-dtc-runtime-tm_31bf3856ad364e35 [10.0.22621.2506] -> msdtctm.dll
amd64_microsoft-windows-com-dtc-runtime_31bf3856ad364e35 [10.0.22621.2506] -> msdtc.exe, msdtckrm.dll
amd64_microsoft-windows-com-dtc-setup_31bf3856ad364e35 [10.0.22621.2506] -> msdtcstp.dll
amd64_microsoft-windows-com-msmq_31bf3856ad364e35 [10.0.22621.2506] -> mqlogmgr.dll
amd64_microsoft-windows-com-oleui_31bf3856ad364e35 [10.0.22621.2506] -> oledlg.dll
amd64_microsoft-windows-com-runtimebroker_31bf3856ad364e35 [10.0.22621.2506] -> runtimebroker.exe
amd64_microsoft-windows-comdlg32_31bf3856ad364e35 [10.0.22621.2506] -> comdlg32.dll
amd64_microsoft-windows-commandprompt_31bf3856ad364e35 [10.0.22621.2506] -> cmd.exe
amd64_microsoft-windows-commonlog_31bf3856ad364e35 [10.0.22621.2715] * -> clfs.sys
amd64_microsoft-windows-compat-appraiser_31bf3856ad364e35 [10.0.22621.2506] -> acmigration.dll, appraiser.dll, win32compatibilityappraisercsp.dll
amd64_microsoft-windows-compat-compattelrunner_31bf3856ad364e35 [10.0.22621.2506] -> compattelrunner.exe
amd64_microsoft-windows-compat-generaltel_31bf3856ad364e35 [10.0.22621.2506] -> generaltel.dll
amd64_microsoft-windows-component-opcom_31bf3856ad364e35 [10.0.22621.2506] -> opcservices.dll
amd64_microsoft-windows-composerframework_31bf3856ad364e35 [10.0.22621.2506] -> windowsinternal.composableshell.display.dll
amd64_microsoft-windows-computer-name-ui_31bf3856ad364e35 [10.0.22621.2506] -> netid.dll
amd64_microsoft-windows-consolelogon-library_31bf3856ad364e35 [10.0.22621.2506] -> consolelogon.dll
amd64_microsoft-windows-container-manager_31bf3856ad364e35 [10.0.22621.2506] -> cmclient.dll, cmdiag.exe, cmimageworker.exe, cmproxyd.exe, cmservice.dll
amd64_microsoft-windows-containers-ccg_31bf3856ad364e35 [10.0.22621.2506] -> ccg.exe
amd64_microsoft-windows-containers-image_31bf3856ad364e35 [10.0.22621.2506] -> wcimage.dll
amd64_microsoft-windows-containers-library_31bf3856ad364e35 [10.0.22621.2506] -> container.dll
amd64_microsoft-windows-coreinkrecognition_31bf3856ad364e35 [10.0.22621.2506] -> mshwrwisp.dll, mshwstaging.dll
amd64_microsoft-windows-coreshell_31bf3856ad364e35 [10.0.22621.2506] -> coreshell.dll
amd64_microsoft-windows-coreshellapi_31bf3856ad364e35 [10.0.22621.2506] -> coreshellapi.dll
amd64_microsoft-windows-coreshellextframework_31bf3856ad364e35 [10.0.22621.2506] -> coreshellextframework.dll
amd64_microsoft-windows-coresystem-smsrouter_31bf3856ad364e35 [10.0.22621.2506] -> smsroutersvc.dll, wsplib.dll
amd64_microsoft-windows-coresystem-wpr_31bf3856ad364e35 [10.0.22621.2506] -> windowsperformancerecordercontrol.dll, wpr.exe
amd64_microsoft-windows-coreuicomponents_31bf3856ad364e35 [10.0.22621.2506] -> coreuicomponents.dll
amd64_microsoft-windows-cpfilters_31bf3856ad364e35 [10.0.22621.2715] * -> cpfilters.dll
amd64_microsoft-windows-crashdump_31bf3856ad364e35 [10.0.22621.2506] -> crashdmp.sys
amd64_microsoft-windows-creddialogcontroller_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.creddialogcontroller.dll
amd64_microsoft-windows-credprovhelper-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovhelper.dll
amd64_microsoft-windows-credprovhost-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovhost.dll
amd64_microsoft-windows-credui-onecore_31bf3856ad364e35 [10.0.22621.2506] -> credui.dll
amd64_microsoft-windows-credwiz_31bf3856ad364e35 [10.0.22621.2506] -> credwiz.exe
amd64_microsoft-windows-crypt32-dll_31bf3856ad364e35 [10.0.22621.2506] -> crypt32.dll
amd64_microsoft-windows-cryptcatsvc-dll_31bf3856ad364e35 [10.0.22621.2506] -> cryptcatsvc.dll
amd64_microsoft-windows-cryptsp-dll_31bf3856ad364e35 [10.0.22621.2506] -> cryptsp.dll
amd64_microsoft-windows-crypttpmeksvc-dll_31bf3856ad364e35 [10.0.22621.2506] -> crypttpmeksvc.dll
amd64_microsoft-windows-cryptui-dll_31bf3856ad364e35 [10.0.22621.2506] -> cryptui.dll
amd64_microsoft-windows-cxhprovisioning_31bf3856ad364e35 [10.0.22621.2506] -> cxhprovisioningserver.dll
amd64_microsoft-windows-d..-certificateinstall_31bf3856ad364e35 [10.0.22621.2506] -> dmcertinst.exe
amd64_microsoft-windows-d..-charcodedictionary_31bf3856ad364e35 [10.0.22621.2506] -> imjpcd.dll
amd64_microsoft-windows-d..-commandline-dsdiag_31bf3856ad364e35 [10.0.22621.2506] -> dcdiag.exe
amd64_microsoft-windows-d..-commandline-dsmgmt_31bf3856ad364e35 [10.0.22621.2506] -> dsmgmt.exe
amd64_microsoft-windows-d..-commandline-netdom_31bf3856ad364e35 [10.0.22621.2506] -> netdom.exe
amd64_microsoft-windows-d..-eashared-imebroker_31bf3856ad364e35 [10.0.22621.2506] -> imebroker.exe, imebrokerps.dll
amd64_microsoft-windows-d..-externaldictionary_31bf3856ad364e35 [10.0.22621.2506] -> imewdbld.exe
amd64_microsoft-windows-d..-japanese-lmprofile_31bf3856ad364e35 [10.0.22621.2506] -> imjplmp.dll
amd64_microsoft-windows-d..-japanese-migration_31bf3856ad364e35 [10.0.22621.2506] -> imjpmig.dll
amd64_microsoft-windows-d..-japanese-nameinput_31bf3856ad364e35 [10.0.22621.2506] -> imjpcmld.dll
amd64_microsoft-windows-d..-japanese-utilities_31bf3856ad364e35 [10.0.22621.2506] -> imjpdct.exe, imjpdctp.dll, imjpuex.exe
amd64_microsoft-windows-d..-mmc-usersandgroups_31bf3856ad364e35 [10.0.22621.2506] -> localsec.dll
amd64_microsoft-windows-d..-pointofservice-daf_31bf3856ad364e35 [10.0.22621.2506] -> dafpos.dll
amd64_microsoft-windows-d..-tools-mmc-adsiedit_31bf3856ad364e35 [10.0.22621.2506] -> adsiedit.dll
amd64_microsoft-windows-d..-warp-jitexecutable_31bf3856ad364e35 [10.0.22621.2506] -> windows.warp.jitservice.exe
amd64_microsoft-windows-d..-winproviders-image_31bf3856ad364e35 [10.0.22621.2506] -> cbsprovider.dll, dmiprovider.dll, genericprovider.dll, intlprovider.dll, offlinesetupprovider.dll, osprovider.dll, provprovider.dll, smiprovider.dll, unattendprovider.dll
amd64_microsoft-windows-d..-winproviders-local_31bf3856ad364e35 [10.0.22621.2506] -> ffuprovider.dll, imagingprovider.dll, vhdprovider.dll, wimprovider.dll
amd64_microsoft-windows-d..-winproviders-winpe_31bf3856ad364e35 [10.0.22621.2506] -> peprovider.dll
amd64_microsoft-windows-d..advancedds-binaries_31bf3856ad364e35 [10.0.22621.2506] -> chxadvancedds.dll
amd64_microsoft-windows-d..agement-omadmclient_31bf3856ad364e35 [10.0.22621.2506] -> omadmclient.exe
amd64_microsoft-windows-d..allationgrouppolicy_31bf3856ad364e35 [10.0.22621.2506] -> pnppolicy.dll
amd64_microsoft-windows-d..anagement-dynamoapi_31bf3856ad364e35 [10.0.22621.2506] -> dynamoapi.dll
amd64_microsoft-windows-d..anager-unenrollhook_31bf3856ad364e35 [10.0.22621.2506] -> unenrollhook.dll
amd64_microsoft-windows-d..andlinepropertytool_31bf3856ad364e35 [10.0.22621.2506] -> imjpuexc.exe
amd64_microsoft-windows-d..anese-softkeyapplet_31bf3856ad364e35 [10.0.22621.2506] -> imjpskey.dll
amd64_microsoft-windows-d..ar-settingshandlers_31bf3856ad364e35 [10.0.22621.2715] * -> settingshandlers_desktoptaskbar.dll
amd64_microsoft-windows-d..ashared-candidateui_31bf3856ad364e35 [10.0.22621.2506] -> mscand20.dll
amd64_microsoft-windows-d..ashared-filemanager_31bf3856ad364e35 [10.0.22621.2506] -> imefiles.dll
amd64_microsoft-windows-d..cemanagement-dmcsps_31bf3856ad364e35 [10.0.22621.2506] -> dmcsps.dll
amd64_microsoft-windows-d..ces-ime-eashared-lm_31bf3856ad364e35 [10.0.22621.2506] -> imelm.dll
amd64_microsoft-windows-d..changjieds-binaries_31bf3856ad364e35 [10.0.22621.2506] -> chtchangjieds.dll
amd64_microsoft-windows-d..characterlistapplet_31bf3856ad364e35 [10.0.22621.2506] -> imjpclst.dll
amd64_microsoft-windows-d..claredconfiguration_31bf3856ad364e35 [10.0.22621.2506] -> declaredconfiguration.dll
amd64_microsoft-windows-d..ctoryclient-onecore_31bf3856ad364e35 [10.0.22621.2506] -> devicedirectoryclient.dll
amd64_microsoft-windows-d..ctoryservices-lsadb_31bf3856ad364e35 [10.0.22621.2506] -> lsadb.dll
amd64_microsoft-windows-d..ctoryservices-ntdsa_31bf3856ad364e35 [10.0.22621.2506] -> ntdsa.dll
amd64_microsoft-windows-d..ctoryservices-setup_31bf3856ad364e35 [10.0.22621.2506] -> ntdsetup.dll
amd64_microsoft-windows-d..ctx-warp-jitservice_31bf3856ad364e35 [10.0.22621.2506] -> windows.warp.jitservice.dll
amd64_microsoft-windows-d..d-searchintegration_31bf3856ad364e35 [10.0.22621.2506] -> imesearch.exe, imesearchdll.dll, imesearchps.dll
amd64_microsoft-windows-d..direct3dshadercache_31bf3856ad364e35 [10.0.22621.2506] -> d3dscache.dll
amd64_microsoft-windows-d..e-coretipjpnprofile_31bf3856ad364e35 [10.0.22621.2506] -> imjptip.dll
amd64_microsoft-windows-d..e-eashared-kjshared_31bf3856ad364e35 [10.0.22621.2506] -> imjkapi.dll
amd64_microsoft-windows-d..e-handwritingapplet_31bf3856ad364e35 [10.0.22621.2506] -> imjpcac.dll
amd64_microsoft-windows-d..e-protocolproviders_31bf3856ad364e35 [10.0.22621.2506] -> barcodescannerprotocolprovider.dll, cashdrawerprotocolprovider.dll, printerprotocolprovider.dll
amd64_microsoft-windows-d..ecomponent-binaries_31bf3856ad364e35 [10.0.22621.2506] -> chsifecomp.dll
amd64_microsoft-windows-d..einstallationclient_31bf3856ad364e35 [10.0.22621.2506] -> devicesoftwareinstallationclient.dll
amd64_microsoft-windows-d..ent-dmpolicymanager_31bf3856ad364e35 [10.0.22621.2715] * -> policymanager.dll
amd64_microsoft-windows-d..ent-gpcsewrappercsp_31bf3856ad364e35 [10.0.22621.2506] -> gpcsewrappercsp.dll
amd64_microsoft-windows-d..ent-prauthproviders_31bf3856ad364e35 [10.0.22621.2506] -> prauthproviders.dll
amd64_microsoft-windows-d..ent-services-client_31bf3856ad364e35 [10.0.22621.2506] -> wdsclient.exe
amd64_microsoft-windows-d..ent-services-server_31bf3856ad364e35 [10.0.22621.2506] -> wdssrv.dll
amd64_microsoft-windows-d..ermanagementconsole_31bf3856ad364e35 [10.0.22621.2506] -> dhcpsnap.dll
amd64_microsoft-windows-d..erver-wmiv2provider_31bf3856ad364e35 [10.0.22621.2506] -> dnsserverpsprovider.dll
amd64_microsoft-windows-d..es-adam-core-client_31bf3856ad364e35 [10.0.22621.2506] -> adammsg.dll, adamssip.dll
amd64_microsoft-windows-d..es-multicast-client_31bf3856ad364e35 [10.0.22621.2506] -> wdsmcast.exe
amd64_microsoft-windows-d..es-smartcards-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.smartcards.dll
amd64_microsoft-windows-d..esflowhost.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> devicesflowhost.exe
amd64_microsoft-windows-d..frameworks-usermode_31bf3856ad364e35 [10.0.22621.2506] -> wudfcompanionhost.exe, wudfhost.exe, wudfpf.sys, wudfplatform.dll, wudfrd.sys
amd64_microsoft-windows-d..gement-dmwappushsvc_31bf3856ad364e35 [10.0.22621.2506] -> dmwappushsvc.dll
amd64_microsoft-windows-d..ice-daf-pospayments_31bf3856ad364e35 [10.0.22621.2506] -> pospaymentsworker.exe
amd64_microsoft-windows-d..ient-server-library_31bf3856ad364e35 [10.0.22621.2506] -> wdscsl.dll
amd64_microsoft-windows-d..ime-eashared-imepad_31bf3856ad364e35 [10.0.22621.2506] -> imepadsm.dll, imepadsv.exe, padrs404.dll, padrs411.dll, padrs804.dll
amd64_microsoft-windows-d..in-tools-mmc-schema_31bf3856ad364e35 [10.0.22621.2506] -> schmmgmt.dll
amd64_microsoft-windows-d..japanese-customizer_31bf3856ad364e35 [10.0.22621.2506] -> imjpcus.dll
amd64_microsoft-windows-d..japanese-prediction_31bf3856ad364e35 [10.0.22621.2506] -> imjppred.dll
amd64_microsoft-windows-d..japanese-propertyui_31bf3856ad364e35 [10.0.22621.2506] -> imjputyc.dll
amd64_microsoft-windows-d..lekanjifinderapplet_31bf3856ad364e35 [10.0.22621.2506] -> imjpskf.dll
amd64_microsoft-windows-d..management-coredpus_31bf3856ad364e35 [10.0.22621.2506] -> coredpus.dll
amd64_microsoft-windows-d..management-firewall_31bf3856ad364e35 [10.0.22621.2506] -> fwmdmcsp.dll
amd64_microsoft-windows-d..management-omadmapi_31bf3856ad364e35 [10.0.22621.2715] * -> omadmapi.dll
amd64_microsoft-windows-d..management-omadmprc_31bf3856ad364e35 [10.0.22621.2715] * -> omadmprc.exe
amd64_microsoft-windows-d..mc-domainsandtrusts_31bf3856ad364e35 [10.0.22621.2506] -> domadmin.dll
amd64_microsoft-windows-d..mc-sitesandservices_31bf3856ad364e35 [10.0.22621.2506] -> dsadmin.dll
amd64_microsoft-windows-d..me-eashared-coretip_31bf3856ad364e35 [10.0.22621.2506] -> imetip.dll
amd64_microsoft-windows-d..me-japanese-dictapi_31bf3856ad364e35 [10.0.22621.2506] -> imjpdapi.dll
amd64_microsoft-windows-d..me-japanese-setting_31bf3856ad364e35 [10.0.22621.2506] -> imjpset.exe
amd64_microsoft-windows-d..ment-configmanager2_31bf3856ad364e35 [10.0.22621.2506] -> configmanager2.dll
amd64_microsoft-windows-d..ment-enterprisecsps_31bf3856ad364e35 [10.0.22621.2715] * -> enterprisecsps.dll
amd64_microsoft-windows-d..n-tools-command-ldp_31bf3856ad364e35 [10.0.22621.2506] -> ldp.exe
amd64_microsoft-windows-d..nagement-dmcfgutils_31bf3856ad364e35 [10.0.22621.2506] -> dmcfgutils.dll
amd64_microsoft-windows-d..nagement-dmcmnutils_31bf3856ad364e35 [10.0.22621.2506] -> dmcmnutils.dll
amd64_microsoft-windows-d..ndowmanager-effects_31bf3856ad364e35 [10.0.22621.2506] -> wuceffects.dll
amd64_microsoft-windows-d..ndowmanager-process_31bf3856ad364e35 [10.0.22621.2506] -> dwm.exe
amd64_microsoft-windows-d..nese-eacommonapijpn_31bf3856ad364e35 [10.0.22621.2506] -> imjpapi.dll
amd64_microsoft-windows-d..nframeworkmigration_31bf3856ad364e35 [10.0.22621.2506] -> dafmigplugin.dll
amd64_microsoft-windows-d..njifinderdictionary_31bf3856ad364e35 [10.0.22621.2506] -> imjpkdic.dll
amd64_microsoft-windows-d..nt-dmpushroutercore_31bf3856ad364e35 [10.0.22621.2715] * -> dmpushroutercore.dll
amd64_microsoft-windows-d..ointofservice-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.pointofservice.dll
amd64_microsoft-windows-d..omerfeedbackmanager_31bf3856ad364e35 [10.0.22621.2506] -> imecfm.dll, imecfmps.dll, imecfmui.exe
amd64_microsoft-windows-d..ommandline-adamsync_31bf3856ad364e35 [10.0.22621.2506] -> adamsync.exe
amd64_microsoft-windows-d..ommandline-dsdbutil_31bf3856ad364e35 [10.0.22621.2506] -> dsdbutil.exe
amd64_microsoft-windows-d..ommandline-ntdsutil_31bf3856ad364e35 [10.0.22621.2506] -> ntdsutil.exe
amd64_microsoft-windows-d..ommandline-repadmin_31bf3856ad364e35 [10.0.22621.2506] -> repadmin.exe
amd64_microsoft-windows-d..opactivitymoderator_31bf3856ad364e35 [10.0.22621.2506] -> dam.sys
amd64_microsoft-windows-d..opwindowmanager-api_31bf3856ad364e35 [10.0.22621.2506] -> dwmapi.dll
amd64_microsoft-windows-d..oryservices-dsparse_31bf3856ad364e35 [10.0.22621.2506] -> dsparse.dll
amd64_microsoft-windows-d..oryservices-ntdsapi_31bf3856ad364e35 [10.0.22621.2506] -> ntdsapi.dll, w32topl.dll
amd64_microsoft-windows-d..oryservices-ntdsatq_31bf3856ad364e35 [10.0.22621.2506] -> ntdsatq.dll
amd64_microsoft-windows-d..pisetexthostdesktop_31bf3856ad364e35 [10.0.22621.2506] -> dmapisetextimpldesktop.dll
amd64_microsoft-windows-d..pwindowmanager-udwm_31bf3856ad364e35 [10.0.22621.2506] -> udwm.dll
amd64_microsoft-windows-d..redconfigurationsvc_31bf3856ad364e35 [10.0.22621.2506] -> dcsvc.dll
amd64_microsoft-windows-d..riseresourcemanager_31bf3856ad364e35 [10.0.22621.2506] -> enterpriseresourcemanager.dll
amd64_microsoft-windows-d..ryoptimization-mgmt_31bf3856ad364e35 [10.0.22621.2506] -> domgmt.dll
amd64_microsoft-windows-d..s-ime-eashared-ihds_31bf3856ad364e35 [10.0.22621.2506] -> ihds.dll
amd64_microsoft-windows-d..se-quickds-binaries_31bf3856ad364e35 [10.0.22621.2506] -> chtquickds.dll
amd64_microsoft-windows-d..se-roaming-binaries_31bf3856ad364e35 [10.0.22621.2506] -> chsroaming.dll
amd64_microsoft-windows-d..services-adam-setup_31bf3856ad364e35 [10.0.22621.2506] -> adammigrate.dll
amd64_microsoft-windows-d..services-core-files_31bf3856ad364e35 [10.0.22621.2506] -> dsamain.exe, ntdsbmsg.dll, ntdsbsrv.dll, ntdskcc.dll, ntdsmsg.dll
amd64_microsoft-windows-d..settingsenvironment_31bf3856ad364e35 [10.0.22621.2506] -> settingsenvironment.desktop.dll
amd64_microsoft-windows-d..setupmanagerservice_31bf3856ad364e35 [10.0.22621.2506] -> devicesetupmanager.dll
amd64_microsoft-windows-d..t-winproviders-appx_31bf3856ad364e35 [10.0.22621.2506] -> appxprovider.dll
amd64_microsoft-windows-d..t-winproviders-edge_31bf3856ad364e35 [10.0.22621.2506] -> edgeprovider.dll
amd64_microsoft-windows-d..terprisediagnostics_31bf3856ad364e35 [10.0.22621.2715] * -> dmenterprisediagnostics.dll
amd64_microsoft-windows-d..toryservices-ntdsai_31bf3856ad364e35 [10.0.22621.2506] -> ntdsai.dll
amd64_microsoft-windows-d..tx-d3d11_3sdklayers_31bf3856ad364e35 [10.0.22621.2506] -> d3d11_3sdklayers.dll
amd64_microsoft-windows-d..tx-dxgiadaptercache_31bf3856ad364e35 [10.0.22621.2506] -> dxgiadaptercache.exe
amd64_microsoft-windows-d..tx-vsd3dwarp12debug_31bf3856ad364e35 [10.0.22621.2506] -> vsd3dwarpdebug.dll
amd64_microsoft-windows-d..userdictds-binaries_31bf3856ad364e35 [10.0.22621.2506] -> chxuserdictds.dll
amd64_microsoft-windows-d..veryoptimization-mi_31bf3856ad364e35 [10.0.22621.2506] -> domiprov.dll
amd64_microsoft-windows-d..vices-dsrole-server_31bf3856ad364e35 [10.0.22621.2506] -> dsrolesrv.dll
amd64_microsoft-windows-d..windowmanager-redir_31bf3856ad364e35 [10.0.22621.2506] -> dwmredir.dll
amd64_microsoft-windows-d..wmanager-compositor_31bf3856ad364e35 [10.0.22621.2715] * -> dwmcore.dll
amd64_microsoft-windows-d2d_31bf3856ad364e35 [10.0.22621.2506] -> d2d1.dll
amd64_microsoft-windows-dafescl_31bf3856ad364e35 [10.0.22621.2506] -> dafescl.dll
amd64_microsoft-windows-dafipp_31bf3856ad364e35 [10.0.22621.2506] -> dafipp.dll
amd64_microsoft-windows-dafmcp_31bf3856ad364e35 [10.0.22621.2506] -> dafmcp.dll
amd64_microsoft-windows-dafwfdprovider_31bf3856ad364e35 [10.0.22621.2506] -> dafwfdprovider.dll
amd64_microsoft-windows-dafwsd_31bf3856ad364e35 [10.0.22621.2506] -> dafwsd.dll
amd64_microsoft-windows-data-activities_31bf3856ad364e35 [10.0.22621.2506] -> windows.data.activities.dll
amd64_microsoft-windows-data-pdf_31bf3856ad364e35 [10.0.22621.2506] -> windows.data.pdf.dll
amd64_microsoft-windows-datacenterbridging_31bf3856ad364e35 [10.0.22621.2506] -> dcbwmi.dll, msdcb.sys
amd64_microsoft-windows-dataclen_31bf3856ad364e35 [10.0.22621.2506] -> dataclen.dll
amd64_microsoft-windows-dataexchange-api_31bf3856ad364e35 [10.0.22621.2506] -> dataexchange.dll
amd64_microsoft-windows-dataexchangehost_31bf3856ad364e35 [10.0.22621.2506] -> dataexchangehost.exe
amd64_microsoft-windows-dataintegrityscan_31bf3856ad364e35 [10.0.22621.2506] -> discan.dll
amd64_microsoft-windows-ddores_31bf3856ad364e35 [10.0.22621.2506] -> ddores.dll
amd64_microsoft-windows-debughelp_31bf3856ad364e35 [10.0.22621.2506] -> dbghelp.dll
amd64_microsoft-windows-deliveryoptimization_31bf3856ad364e35 [10.0.22621.2506] -> doclient.dll, dosvc.dll
amd64_microsoft-windows-deltacompressionengine_31bf3856ad364e35 [10.0.22621.2506] -> msdelta.dll, mspatcha.dll, mspatchc.dll
amd64_microsoft-windows-deltapackageexpander_31bf3856ad364e35 [10.0.22621.2506] -> dpx.dll
amd64_microsoft-windows-desk_31bf3856ad364e35 [10.0.22621.2506] -> desk.cpl
amd64_microsoft-windows-desktopactivitybroker_31bf3856ad364e35 [10.0.22621.2506] -> dab.dll
amd64_microsoft-windows-desktopdispbroker_31bf3856ad364e35 [10.0.22621.2506] -> dispbroker.desktop.dll
amd64_microsoft-windows-desktopshellext_31bf3856ad364e35 [10.0.22621.2506] -> desktopshellext.dll
amd64_microsoft-windows-desktopview.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> desktopview.exe
amd64_microsoft-windows-devdispitemprovider_31bf3856ad364e35 [10.0.22621.2506] -> devdispitemprovider.dll
amd64_microsoft-windows-developersetupcsp_31bf3856ad364e35 [10.0.22621.2506] -> developersetupcsp.dll
amd64_microsoft-windows-devicecensus_31bf3856ad364e35 [10.0.22621.2506] -> dcntel.dll, devicecensus.exe
amd64_microsoft-windows-devicecenter_31bf3856ad364e35 [10.0.22621.2506] -> devicecenter.dll
amd64_microsoft-windows-deviceconfidence_31bf3856ad364e35 [10.0.22621.2506] -> consentux.dll
amd64_microsoft-windows-deviceenroller_31bf3856ad364e35 [10.0.22621.2715] * -> deviceenroller.exe
amd64_microsoft-windows-deviceflows-datamodel_31bf3856ad364e35 [10.0.22621.2506] -> deviceflows.datamodel.dll
amd64_microsoft-windows-deviceguard-gpext_31bf3856ad364e35 [10.0.22621.2506] -> dggpext.dll
amd64_microsoft-windows-deviceguard-wmi_31bf3856ad364e35 [10.0.22621.2506] -> win32_deviceguard.dll
amd64_microsoft-windows-devicepairingdll_31bf3856ad364e35 [10.0.22621.2506] -> devicepairing.dll
amd64_microsoft-windows-devicepairingfolder_31bf3856ad364e35 [10.0.22621.2506] -> devicepairingfolder.dll
amd64_microsoft-windows-devices-background_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.background.dll, windows.devices.background.ps.dll
amd64_microsoft-windows-devices-bluetooth_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.bluetooth.dll
amd64_microsoft-windows-devices-custom_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.custom.dll, windows.devices.custom.ps.dll
amd64_microsoft-windows-devices-enumeration_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.enumeration.dll
amd64_microsoft-windows-devices-lights-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.lights.dll
amd64_microsoft-windows-devices-radios_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.radios.dll
amd64_microsoft-windows-devices-wifi_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.wifi.dll
amd64_microsoft-windows-devices-wifidirect_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.wifidirect.dll
amd64_microsoft-windows-devicesetupmanagerapi_31bf3856ad364e35 [10.0.22621.2506] -> devicesetupmanagerapi.dll, dsmusertask.exe
amd64_microsoft-windows-devicesflowbroker_31bf3856ad364e35 [10.0.22621.2506] -> devicesflowbroker.dll
amd64_microsoft-windows-devicesflowui-fod_31bf3856ad364e35 [10.0.22621.2506] -> devicesflowui.app.dll
amd64_microsoft-windows-dfsclient_31bf3856ad364e35 [10.0.22621.2506] -> dfsc.sys
amd64_microsoft-windows-dhcp-client-dll-minwin_31bf3856ad364e35 [10.0.22621.2506] -> dhcpcore.dll, dhcpcore6.dll, dhcpcsvc.dll, dhcpcsvc6.dll
amd64_microsoft-windows-dhcpds_31bf3856ad364e35 [10.0.22621.2506] -> dsauth.dll
amd64_microsoft-windows-dhcpserverapi_31bf3856ad364e35 [10.0.22621.2506] -> dhcpsapi.dll
amd64_microsoft-windows-dial-server-dll_31bf3856ad364e35 [10.0.22621.2506] -> dialserver.dll
amd64_microsoft-windows-dims-keyroam_31bf3856ad364e35 [10.0.22621.2506] -> adprovider.dll, capiprovider.dll, cngprovider.dll, dimsroam.dll, dpapiprovider.dll, wincredprovider.dll
amd64_microsoft-windows-directcomposition_31bf3856ad364e35 [10.0.22621.2715] * -> dcomp.dll
amd64_microsoft-windows-directmanipulation_31bf3856ad364e35 [10.0.22621.2506] -> directmanipulation.dll
amd64_microsoft-windows-directory-services-sam_31bf3856ad364e35 [10.0.22621.2506] -> offlinesam.dll, samlib.dll, samsrv.dll
amd64_microsoft-windows-directshow-core_31bf3856ad364e35 [10.0.22621.2506] -> quartz.dll
amd64_microsoft-windows-directshow-dvdsupport_31bf3856ad364e35 [10.0.22621.2506] -> qdvd.dll
amd64_microsoft-windows-directui_31bf3856ad364e35 [10.0.22621.2715] * -> windows.ui.xaml.dll, windows.ui.xaml.resources.common.dll
amd64_microsoft-windows-directwrite-fontcache_31bf3856ad364e35 [10.0.22621.2506] -> fntcache.dll
amd64_microsoft-windows-directwrite_31bf3856ad364e35 [10.0.22621.2506] -> dwrite.dll, textshaping.dll
amd64_microsoft-windows-directx-d2d1debug3_31bf3856ad364e35 [10.0.22621.2506] -> d2d1debug3.dll
amd64_microsoft-windows-directx-d3d10level9_31bf3856ad364e35 [10.0.22621.2506] -> d3d10level9.dll
amd64_microsoft-windows-directx-d3d12sdklayers_31bf3856ad364e35 [10.0.22621.2506] -> d3d12sdklayers.dll
amd64_microsoft-windows-directx-d3dcompiler_31bf3856ad364e35 [10.0.22621.2506] -> d3dcompiler_47.dll
amd64_microsoft-windows-directx-ddisplay_31bf3856ad364e35 [10.0.22621.2506] -> ddisplay.dll
amd64_microsoft-windows-directx-direct3d10.1_31bf3856ad364e35 [10.0.22621.2506] -> d3d10_1.dll, d3d10_1core.dll
amd64_microsoft-windows-directx-direct3d11_31bf3856ad364e35 [10.0.22621.2506] -> d3d11.dll
amd64_microsoft-windows-directx-direct3d11on12_31bf3856ad364e35 [10.0.22621.2506] -> d3d11on12.dll
amd64_microsoft-windows-directx-direct3d12_31bf3856ad364e35 [10.0.22621.2506] -> d3d12.dll, d3d12core.dll
amd64_microsoft-windows-directx-direct3d9_31bf3856ad364e35 [10.0.22621.2506] -> d3d8thk.dll, d3d9.dll
amd64_microsoft-windows-directx-direct3d9on12_31bf3856ad364e35 [10.0.22621.2506] -> d3d9on12.dll
amd64_microsoft-windows-directx-dxgi_31bf3856ad364e35 [10.0.22621.2506] -> dxgi.dll
amd64_microsoft-windows-directx-gpm_31bf3856ad364e35 [10.0.22621.2506] -> graphicsperfsvc.dll
amd64_microsoft-windows-directx-warp10_31bf3856ad364e35 [10.0.22621.2506] -> d3d10warp.dll
amd64_microsoft-windows-diskusage_31bf3856ad364e35 [10.0.22621.2506] -> diskusage.exe
amd64_microsoft-windows-dispdiag_31bf3856ad364e35 [10.0.22621.2506] -> dispdiag.exe
amd64_microsoft-windows-displaymanager_31bf3856ad364e35 [10.0.22621.2506] -> displaymanager.dll
amd64_microsoft-windows-displayswitch_31bf3856ad364e35 [10.0.22621.2506] -> displayswitch.exe
amd64_microsoft-windows-dlna-dmrserver_31bf3856ad364e35 [10.0.22621.2715] * -> dmrserver.dll
amd64_microsoft-windows-dns-client-minwin_31bf3856ad364e35 [10.0.22621.2506] -> dnsapi.dll, dnsrslvr.dll
amd64_microsoft-windows-dns-clientsnapin_31bf3856ad364e35 [10.0.22621.2506] -> dnscmmc.dll
amd64_microsoft-windows-dns-server-dnscmd_31bf3856ad364e35 [10.0.22621.2506] -> dnscmd.exe
amd64_microsoft-windows-dns-server-snapin_31bf3856ad364e35 [10.0.22621.2506] -> dnsmgr.dll
amd64_microsoft-windows-dnssd-dafprovider_31bf3856ad364e35 [10.0.22621.2506] -> dafdnssd.dll
amd64_microsoft-windows-dolbyatmosdecmft_31bf3856ad364e35 [10.0.22621.2715] * -> dolbydecmft.dll
amd64_microsoft-windows-dot3mm_31bf3856ad364e35 [10.0.22621.2506] -> dot3mm.dll
amd64_microsoft-windows-dot3svc_31bf3856ad364e35 [10.0.22621.2506] -> dot3api.dll, dot3msm.dll, dot3svc.dll, wirednetworkcsp.dll
amd64_microsoft-windows-dpapisrv-dll_31bf3856ad364e35 [10.0.22621.2506] -> dpapisrv.dll
amd64_microsoft-windows-dpl-csp_31bf3856ad364e35 [10.0.22621.2506] -> dplcsp.dll
amd64_microsoft-windows-driververifier-xdv_31bf3856ad364e35 [10.0.22621.2506] -> verifierext.sys
amd64_microsoft-windows-drvstore_31bf3856ad364e35 [10.0.22621.2506] -> drvstore.dll
amd64_microsoft-windows-ducupdateagent_31bf3856ad364e35 [10.0.22621.2506] -> ducupdateagent.dll
amd64_microsoft-windows-dui70_31bf3856ad364e35 [10.0.22621.2506] -> dui70.dll
amd64_microsoft-windows-dusm_31bf3856ad364e35 [10.0.22621.2506] -> dusmsvc.dll, dusmtask.exe
amd64_microsoft-windows-dxp-deviceexperience_31bf3856ad364e35 [10.0.22621.2506] -> dxp.dll, dxpps.dll, dxpserver.exe
amd64_microsoft-windows-e..-management-onecore_31bf3856ad364e35 [10.0.22621.2506] -> enterpriseappmgmtclient.dll, enterpriseappmgmtsvc.dll
amd64_microsoft-windows-e..-mdmdiagnosticstool_31bf3856ad364e35 [10.0.22621.2506] -> mdmdiagnosticstool.exe
amd64_microsoft-windows-e..-protocol-host-peer_31bf3856ad364e35 [10.0.22621.2506] -> eapp3hst.dll, eappcfg.dll, eappgnui.dll, eapphost.dll, eappprxy.dll
amd64_microsoft-windows-e..-unifiedwritefilter_31bf3856ad364e35 [10.0.22621.2506] -> uwfservicingshell.exe, uwfservicingsvc.exe, uwfwmi.dll
amd64_microsoft-windows-e..alogblockingservice_31bf3856ad364e35 [10.0.22621.2506] -> dialogblockingmanager.dll, dialogblockingservice.dll
amd64_microsoft-windows-e..crosoftedgedevtools_31bf3856ad364e35 [10.0.22621.2506] -> microsoftedgedevtools.exe
amd64_microsoft-windows-e..estorageengine-isam_31bf3856ad364e35 [10.0.22621.2506] -> esent.dll
amd64_microsoft-windows-e..gationconfiguration_31bf3856ad364e35 [10.0.22621.2506] -> mitigationconfiguration.dll
amd64_microsoft-windows-e..ilterservice-client_31bf3856ad364e35 [10.0.22621.2506] -> keyboardfiltermanager.dll, keyboardfiltersvc.dll
amd64_microsoft-windows-e..llment-winrt-client_31bf3856ad364e35 [10.0.22621.2506] -> dmalertlistener.proxystub.dll, windows.internal.management.dll
amd64_microsoft-windows-e..mgmt-mdmdiagnostics_31bf3856ad364e35 [10.0.22621.2506] -> mdmdiagnostics.dll
amd64_microsoft-windows-e..microsoftedgebchost_31bf3856ad364e35 [10.0.22621.2506] -> microsoftedgebchost.exe
amd64_microsoft-windows-e..ortingcompatibility_31bf3856ad364e35 [10.0.22621.2506] -> dwwin.exe
amd64_microsoft-windows-e..riseclientsync-host_31bf3856ad364e35 [10.0.22621.2506] -> workfolders.exe, workfolderscontrol.dll, workfoldersshell.dll, workfolderssvc.dll
amd64_microsoft-windows-e..sedesktopappmgmtcsp_31bf3856ad364e35 [10.0.22621.2506] -> enterprisedesktopappmgmtcsp.dll
amd64_microsoft-windows-e..ymanagementservices_31bf3856ad364e35 [10.0.22621.2506] -> sacdrv.sys, sacsess.exe, sacsvr.dll
amd64_microsoft-windows-eappcfgui_31bf3856ad364e35 [10.0.22621.2506] -> eappcfgui.dll
amd64_microsoft-windows-eapprivateutil_31bf3856ad364e35 [10.0.22621.2506] -> eapputil.dll
amd64_microsoft-windows-eapteap_31bf3856ad364e35 [10.0.22621.2506] -> eapteapauth.dll, eapteapconfig.dll
amd64_microsoft-windows-eapttls_31bf3856ad364e35 [10.0.22621.2506] -> ttlsauth.dll, ttlscfg.dll
amd64_microsoft-windows-ecapp.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> gazeinputinternal.dll, gazeinteraction.dll, microsoft.ecapp.exe
amd64_microsoft-windows-edge-angle_31bf3856ad364e35 [10.0.22621.2506] -> edgeangle.dll
amd64_microsoft-windows-edge-axhost_31bf3856ad364e35 [10.0.22621.2506] -> wpaxholder.dll
amd64_microsoft-windows-edge-edgecontent_31bf3856ad364e35 [10.0.22621.2506] -> edgecontent.dll
amd64_microsoft-windows-edge-edgemanager_31bf3856ad364e35 [10.0.22621.2506] -> webruntimemanager.dll
amd64_microsoft-windows-edition-transmogrifier_31bf3856ad364e35 [10.0.22621.2506] -> transmogprovider.dll
amd64_microsoft-windows-edp-notify_31bf3856ad364e35 [10.0.22621.2506] -> bitlockercsp.dll, edpnotify.exe
amd64_microsoft-windows-edp-task_31bf3856ad364e35 [10.0.22621.2506] -> edptask.dll
amd64_microsoft-windows-efs-core-library_31bf3856ad364e35 [10.0.22621.2506] -> efscore.dll
amd64_microsoft-windows-embedded-lockdownwmi_31bf3856ad364e35 [10.0.22621.2506] -> embeddedlockdownwmi.dll
amd64_microsoft-windows-embedded-shelllauncher_31bf3856ad364e35 [10.0.22621.2506] -> eshell.exe, shelllauncherconfig.dll, shelllauncherconfig.exe, shelllauncherrepository.dll, wesl_shelllauncher.dll
amd64_microsoft-windows-energyefficiencywizard_31bf3856ad364e35 [10.0.22621.2506] -> energy.dll
amd64_microsoft-windows-enhancedvideorenderer_31bf3856ad364e35 [10.0.22621.2506] -> evr.dll
amd64_microsoft-windows-enrollengine_31bf3856ad364e35 [10.0.22621.2715] * -> dmenrollengine.dll, enrollmentapi.dll, mdmmigrator.dll
amd64_microsoft-windows-errorreportingconsole_31bf3856ad364e35 [10.0.22621.2506] -> werconcpl.dll, wercplsupport.dll
amd64_microsoft-windows-errorreportingcore_31bf3856ad364e35 [10.0.22621.2506] -> wer.dll, werdiagcontroller.dll, weretw.dll, wermgr.exe
amd64_microsoft-windows-errorreportingfaults_31bf3856ad364e35 [10.0.22621.2506] -> faultrep.dll, werenc.dll, werfault.exe, werfaultsecure.exe
amd64_microsoft-windows-errorreportingkernel_31bf3856ad364e35 [10.0.22621.2506] -> werkernel.sys
amd64_microsoft-windows-esclprotocol_31bf3856ad364e35 [10.0.22621.2506] -> esclprotocol.dll
amd64_microsoft-windows-esclscan_31bf3856ad364e35 [10.0.22621.2506] -> esclscan.dll
amd64_microsoft-windows-esdsip_31bf3856ad364e35 [10.0.22621.2506] -> esdsip.dll
amd64_microsoft-windows-eventcollector_31bf3856ad364e35 [10.0.22621.2506] -> wecapi.dll, wecsvc.dll, wecutil.exe
amd64_microsoft-windows-eventlog-api_31bf3856ad364e35 [10.0.22621.2506] -> wevtapi.dll
amd64_microsoft-windows-eventlog-commandline_31bf3856ad364e35 [10.0.22621.2506] -> wevtutil.exe
amd64_microsoft-windows-eventlog-forwardplugin_31bf3856ad364e35 [10.0.22621.2506] -> wevtfwd.dll
amd64_microsoft-windows-eventlog_31bf3856ad364e35 [10.0.22621.2506] -> wevtsvc.dll
amd64_microsoft-windows-execmodel-client_31bf3856ad364e35 [10.0.22621.2506] -> execmodelclient.dll
amd64_microsoft-windows-exfat_31bf3856ad364e35 [10.0.22621.2506] -> exfat.sys
amd64_microsoft-windows-explorer_31bf3856ad364e35 [10.0.22621.2715] * -> explorer.exe
amd64_microsoft-windows-explorerframe_31bf3856ad364e35 [10.0.22621.2506] -> explorerframe.dll
amd64_microsoft-windows-f..allconfig-installer_31bf3856ad364e35 [10.0.22621.2506] -> cmifw.dll
amd64_microsoft-windows-f..back-courtesyengine_31bf3856ad364e35 [10.0.22621.2506] -> courtesyengine.dll
amd64_microsoft-windows-f..client-applications_31bf3856ad364e35 [10.0.22621.2506] -> fxscompose.dll, fxscomposeres.dll, fxscover.exe, fxsutility.dll, wfs.exe, wfsr.dll
amd64_microsoft-windows-f..cluster-objectmodel_31bf3856ad364e35 [10.0.22621.2506] -> failoverclusters.objectmodel.dll
amd64_microsoft-windows-f..eatureconfiguration_31bf3856ad364e35 [10.0.22621.2506] -> fcon.dll
amd64_microsoft-windows-f..ependencyminifilter_31bf3856ad364e35 [10.0.22621.2506] -> fsdepends.sys
amd64_microsoft-windows-f..g-onesettingsclient_31bf3856ad364e35 [10.0.22621.2506] -> wosc.dll
amd64_microsoft-windows-f..mutilityrefslibrary_31bf3856ad364e35 [10.0.22621.2506] -> urefs.dll
amd64_microsoft-windows-f..rcluster-clientcore_31bf3856ad364e35 [10.0.22621.2506] -> clusapi.dll, resutils.dll
amd64_microsoft-windows-f..rcluster-validation_31bf3856ad364e35 [10.0.22621.2506] -> failoverclusters.agent.interop.dll, failoverclusters.fcagent.interop.dll, failoverclusters.validation.bestpracticetests.dll, failoverclusters.validation.common.dll, failoverclusters.validation.generaltests.dll, failoverclusters.validation.hypervtests.dll, failoverclusters.validation.storagetests.dll, microsoft.failoverclusters.validation.dll
amd64_microsoft-windows-f..ster-managed-common_31bf3856ad364e35 [10.0.22621.2506] -> clnetcfg.dll, failoverclusters.common.dll
amd64_microsoft-windows-f..temutilitylibraries_31bf3856ad364e35 [10.0.22621.2506] -> ifsutil.dll, ulib.dll
amd64_microsoft-windows-f..tilityrefsv1library_31bf3856ad364e35 [10.0.22621.2506] -> urefsv1.dll
amd64_microsoft-windows-f..utilitylibrariesext_31bf3856ad364e35 [10.0.22621.2506] -> cmdext.dll, fsutilext.dll
amd64_microsoft-windows-f..yphanimator-library_31bf3856ad364e35 [10.0.22621.2506] -> fontglyphanimator.dll
amd64_microsoft-windows-f..ysafety-refreshtask_31bf3856ad364e35 [10.0.22621.2506] -> wpcrefreshtask.dll, wpctok.exe
amd64_microsoft-windows-fat_31bf3856ad364e35 [10.0.22621.2506] -> fastfat.sys
amd64_microsoft-windows-fax-common_31bf3856ad364e35 [10.0.22621.2506] -> fxsapi.dll, fxscom.dll, fxscomex.dll, fxsocm.dll, fxsresm.dll, fxst30.dll, fxstiff.dll, winfax.dll
amd64_microsoft-windows-fax-service_31bf3856ad364e35 [10.0.22621.2506] -> fxsevent.dll, fxsmon.dll, fxsroute.dll, fxssvc.exe, fxsunatd.exe
amd64_microsoft-windows-fax-status-monitor_31bf3856ad364e35 [10.0.22621.2506] -> fxsst.dll
amd64_microsoft-windows-fdeploy_31bf3856ad364e35 [10.0.22621.2506] -> fdeploy.dll, frprov.dll, ustprov.dll
amd64_microsoft-windows-feclient_31bf3856ad364e35 [10.0.22621.2506] -> feclient.dll
amd64_microsoft-windows-feedback-service_31bf3856ad364e35 [10.0.22621.2506] -> wersvc.dll
amd64_microsoft-windows-filebasedwritefilter_31bf3856ad364e35 [10.0.22621.2506] -> fbwf.sys
amd64_microsoft-windows-fileexplorer-common_31bf3856ad364e35 [10.0.22621.2506] -> windows.fileexplorer.common.dll
amd64_microsoft-windows-fileexplorer.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> fileexplorer.exe
amd64_microsoft-windows-filehistory-core-cpl_31bf3856ad364e35 [10.0.22621.2506] -> fhcpl.dll
amd64_microsoft-windows-filehistory-core_31bf3856ad364e35 [10.0.22621.2506] -> fhcat.dll, fhcfg.dll, fhcleanup.dll, fhengine.dll, fhevents.dll, fhmanagew.exe, fhsettingsprovider.dll, fhshl.dll, fhsrchapi.dll, fhsrchph.dll, fhsvc.dll, fhsvcctl.dll, fhtask.dll
amd64_microsoft-windows-filehistory-ui_31bf3856ad364e35 [10.0.22621.2506] -> fhuxadapter.dll, fhuxapi.dll, fhuxcommon.dll, fhuxgraphics.dll, fhuxpresentation.dll, filehistory.exe
amd64_microsoft-windows-filepicker.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> filepicker.exe
amd64_microsoft-windows-filtermanager-core_31bf3856ad364e35 [10.0.22621.2506] -> fltmgr.sys
amd64_microsoft-windows-firewallux_31bf3856ad364e35 [10.0.22621.2506] -> firewallux.dll
amd64_microsoft-windows-flighting-settings_31bf3856ad364e35 [10.0.22621.2506] -> flightsettings.dll
amd64_microsoft-windows-fmifs_31bf3856ad364e35 [10.0.22621.2506] -> fmifs.dll
amd64_microsoft-windows-fodhelper-ux_31bf3856ad364e35 [10.0.22621.2506] -> fodhelper.exe
amd64_microsoft-windows-fontext_31bf3856ad364e35 [10.0.22621.2506] -> fontext.dll
amd64_microsoft-windows-frameworkudk_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.internal.frameworkudk.system.dll
amd64_microsoft-windows-fsd_31bf3856ad364e35 [10.0.22621.2506] -> ntfsres.dll
amd64_microsoft-windows-fsutil_31bf3856ad364e35 [10.0.22621.2506] -> fsutil.exe
amd64_microsoft-windows-ftp_31bf3856ad364e35 [10.0.22621.2506] -> ftp.exe
amd64_microsoft-windows-g..-brightnessoverride_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.display.brightnessoverride.dll
amd64_microsoft-windows-g..ation-wincomponents_31bf3856ad364e35 [10.0.22621.2506] -> locationnotificationwindows.exe, locationwinpalmisc.dll, windowsactiondialog.exe
amd64_microsoft-windows-g..enhancementoverride_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.display.displayenhancementoverride.dll
amd64_microsoft-windows-g..framework-container_31bf3856ad364e35 [10.0.22621.2506] -> locationframeworkps.dll
amd64_microsoft-windows-g..policy-admin-gpedit_31bf3856ad364e35 [10.0.22621.2506] -> gpedit.dll
amd64_microsoft-windows-g..ppolicy-policymaker_31bf3856ad364e35 [10.0.22621.2506] -> gpprefcl.dll
amd64_microsoft-windows-g..rveradmintools-gpmc_31bf3856ad364e35 [10.0.22621.2506] -> gpoadmin.dll, gpoadmincommon.dll, gpoadmincustom.dll
amd64_microsoft-windows-g..rveradmintools-gpme_31bf3856ad364e35 [10.0.22621.2506] -> gpme.dll, gppref.dll, gpprefbr.dll, gpprefcn.dll, gpregistrybrowser.dll, propshts.dll
amd64_microsoft-windows-g..tion-service-modern_31bf3856ad364e35 [10.0.22621.2506] -> lfsvc.dll
amd64_microsoft-windows-g..yenhancementservice_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.graphics.display.displayenhancementservice.dll
amd64_microsoft-windows-gdi-painting_31bf3856ad364e35 [10.0.22621.2506] -> mf3216.dll, msimg32.dll
amd64_microsoft-windows-gdi32_31bf3856ad364e35 [10.0.22621.2506] -> gdi32.dll
amd64_microsoft-windows-gdi32full_31bf3856ad364e35 [10.0.22621.2506] -> gdi32full.dll
amd64_microsoft-windows-gdi_31bf3856ad364e35 [10.0.22621.2506] -> atmlib.dll, dciman32.dll, fontdrvhost.exe, fontsub.dll, lpk.dll
amd64_microsoft-windows-geolocation-framework_31bf3856ad364e35 [10.0.22621.2506] -> locationframework.dll, locationframeworkinternalps.dll, locationframeworkps.dll
amd64_microsoft-windows-geolocation-winrt_31bf3856ad364e35 [10.0.22621.2506] -> geolocation.dll
amd64_microsoft-windows-globalization_31bf3856ad364e35 [10.0.22621.2506] -> windows.globalization.dll
amd64_microsoft-windows-gpio-class-extension_31bf3856ad364e35 [10.0.22621.2506] -> msgpioclx.sys
amd64_microsoft-windows-graphics-dispbroker_31bf3856ad364e35 [10.0.22621.2506] -> dispbroker.dll
amd64_microsoft-windows-graphics-wdi_31bf3856ad364e35 [10.0.22621.2506] -> dxgwdi.dll
amd64_microsoft-windows-graphicscapture_31bf3856ad364e35 [10.0.22621.2506] -> graphicscapture.dll
amd64_microsoft-windows-grouppolicy-base_31bf3856ad364e35 [10.0.22621.2506] -> gpapi.dll, gpsvc.dll
amd64_microsoft-windows-guest-network-service_31bf3856ad364e35 [10.0.22621.2506] -> gns.dll
amd64_microsoft-windows-h..-network-management_31bf3856ad364e35 [10.0.22621.2506] -> netmgmtif.dll, nmbind.exe, nmscrub.exe
amd64_microsoft-windows-h..applicationguardcsp_31bf3856ad364e35 [10.0.22621.2506] -> windowsdefenderapplicationguardcsp.dll
amd64_microsoft-windows-h..deintegrity-sysprep_31bf3856ad364e35 [10.0.22621.2506] -> vbssysprep.dll
amd64_microsoft-windows-h..dspi-classextension_31bf3856ad364e35 [10.0.22621.2506] -> hidspicx.sys
amd64_microsoft-windows-h..forcedcodeintegrity_31bf3856ad364e35 [10.0.22621.2506] -> vbsapi.dll
amd64_microsoft-windows-h..genshell-components_31bf3856ad364e35 [10.0.22621.2506] -> analog.shell.components.dll
amd64_microsoft-windows-h..hextensions-desktop_31bf3856ad364e35 [10.0.22621.2715] * -> holoshextensions.dll
amd64_microsoft-windows-h..public-utils-shared_31bf3856ad364e35 [10.0.22621.2506] -> hvsiproxyapp.exe, isolatedwindowsenvironmentutils.dll
amd64_microsoft-windows-h..work-service-client_31bf3856ad364e35 [10.0.22621.2506] -> computenetwork.dll
amd64_microsoft-windows-hal_31bf3856ad364e35 [10.0.22621.2506] -> hal.dll
amd64_microsoft-windows-healthattestation-csp_31bf3856ad364e35 [10.0.22621.2506] -> azureattestmanager.dll, azureattestnormal.dll, hascsp.dll, healthattestationclientagent.exe
amd64_microsoft-windows-heatcore_31bf3856ad364e35 [10.0.22621.2506] -> heatcore.dll, windowsdefaultheatprocessor.dll
amd64_microsoft-windows-help-client_31bf3856ad364e35 [10.0.22621.2506] -> helppane.exe
amd64_microsoft-windows-hgsclient-wmi_31bf3856ad364e35 [10.0.22621.2506] -> hgsclientwmi.dll
amd64_microsoft-windows-hlink_31bf3856ad364e35 [10.0.22621.2506] -> hlink.dll
amd64_microsoft-windows-hnetcfgclient_31bf3856ad364e35 [10.0.22621.2506] -> hnetcfgclient.dll
amd64_microsoft-windows-holoshell.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> holoshellapp.exe
amd64_microsoft-windows-holoshellruntime_31bf3856ad364e35 [10.0.22621.2506] -> holoshellruntime.dll
amd64_microsoft-windows-holosi-desktop_31bf3856ad364e35 [10.0.22621.2506] -> holosi.pcshell.dll
amd64_microsoft-windows-host-network-service_31bf3856ad364e35 [10.0.22621.2506] -> hnsproxy.dll, hostnetsvc.dll
amd64_microsoft-windows-hsp_31bf3856ad364e35 [10.0.22621.2715] * -> firmwareattestationserverproxystub.dll, hspapi.dll, hspfw.dll
amd64_microsoft-windows-http-api_31bf3856ad364e35 [10.0.22621.2506] -> httpapi.dll
amd64_microsoft-windows-http_31bf3856ad364e35 [10.0.22621.2506] -> http.sys
amd64_microsoft-windows-httpsdatasource_31bf3856ad364e35 [10.0.22621.2506] -> httpsdatasource.dll
amd64_microsoft-windows-hvsi-csp_31bf3856ad364e35 [10.0.22621.2506] -> hvsievaluator.exe
amd64_microsoft-windows-hvsi-management-api_31bf3856ad364e35 [10.0.22621.2506] -> hvsimanagementapi.dll
amd64_microsoft-windows-hvsi-manager-shared_31bf3856ad364e35 [10.0.22621.2506] -> hvsisettingsprovider.dll
amd64_microsoft-windows-hvsi-manager_31bf3856ad364e35 [10.0.22621.2506] -> hvsifiletrust.dll, hvsimgr.exe, hvsimgrps.dll, hvsirdpclient.exe, hvsirpcd.exe, wdagtool.exe
amd64_microsoft-windows-hvsi-service-shared_31bf3856ad364e35 [10.0.22621.2506] -> auditsettingsprovider.dll, hvsimachinepolicies.dll, hvsisettingsworker.exe
amd64_microsoft-windows-hvsi-service_31bf3856ad364e35 [10.0.22621.2506] -> hvsicontainerservice.dll
amd64_microsoft-windows-hwreqchk_31bf3856ad364e35 [10.0.22621.2506] -> hwreqchk.dll
amd64_microsoft-windows-hydrogenshell-console_31bf3856ad364e35 [10.0.22621.2506] -> analog.console.client.dll
amd64_microsoft-windows-hydrogenshell-services_31bf3856ad364e35 [10.0.22621.2506] -> analog.shell.services.dll
amd64_microsoft-windows-hydrogenshell-util_31bf3856ad364e35 [10.0.22621.2506] -> analog.shell.util.dll
amd64_microsoft-windows-hyper-v-vfpext_31bf3856ad364e35 [10.0.22621.2506] -> vfpapi.dll, vfpctrl.exe, vfpext.sys
amd64_microsoft-windows-i..-accountscontrolexp_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.shellcommon.accountscontrolexperience.dll
amd64_microsoft-windows-i..-shellcommon-broker_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.shellcommon.broker.dll
amd64_microsoft-windows-i..-system-userprofile_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.system.userprofile.dll
amd64_microsoft-windows-i..-team-deviceaccount_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.team.deviceaccount.dll
amd64_microsoft-windows-i..-unicode-components_31bf3856ad364e35 [10.0.22621.2506] -> icu.dll, icuin.dll, icuuc.dll
amd64_microsoft-windows-i..2-filesystemsupport_31bf3856ad364e35 [10.0.22621.2506] -> imapi2fs.dll
amd64_microsoft-windows-i..airingexperiencemem_31bf3856ad364e35 [10.0.22621.2506] -> devicepairingexperiencemem.dll
amd64_microsoft-windows-i..al-people-relevance_31bf3856ad364e35 [10.0.22621.2506] -> windowsinternal.people.relevance.dll
amd64_microsoft-windows-i..basedsetup-media-ds_31bf3856ad364e35 [10.0.22621.2506] -> cryptosetup.dll, ntdsupg.dll
amd64_microsoft-windows-i..cachingbasebinaries_31bf3856ad364e35 [10.0.22621.2506] -> cachfile.dll, cachtokn.dll, cachuri.dll
amd64_microsoft-windows-i..chinese-tip_profile_31bf3856ad364e35 [10.0.22621.2506] -> imtctip.dll
amd64_microsoft-windows-i..dia-branding-client_31bf3856ad364e35 [10.0.22621.2506] -> arunimg.dll, arunres.dll, spwizimg.dll, spwizres.dll, w32uires.dll
amd64_microsoft-windows-i..dia-branding-server_31bf3856ad364e35 [10.0.22621.2506] -> arunimg.dll, arunres.dll, spwizimg.dll, spwizres.dll, w32uires.dll
amd64_microsoft-windows-i..displays-kernelmode_31bf3856ad364e35 [10.0.22621.2506] -> indirectkmd.sys
amd64_microsoft-windows-i..dsetup-rejuvenation_31bf3856ad364e35 [10.0.22621.2506] -> cmi2migxml.dll, csiagent.dll, diager.dll, hwcompat.dll, migcore.dll, mighost.exe, migisol.dll, migres.dll, migstore.dll, migsys.dll, mxeagent.dll, pnppropmig.dll, reservemanager.dll, setupplatform.dll, setupplatform.exe, unbcl.dll, upgradeagent.dll, wdsutil.dll, winsetupmon.sys
amd64_microsoft-windows-i..ectionsharingconfig_31bf3856ad364e35 [10.0.22621.2506] -> hnetcfg.dll
amd64_microsoft-windows-i..edia-legacy-onecore_31bf3856ad364e35 [10.0.22621.2506] -> drupdate.dll, esscli.dll, fastprox.dll, mofd.dll, mofinstall.dll, oobeldretw.dll, repdrvfs.dll, setupugcetw.dll, sysprepetw.dll, wbemcomn.dll, wbemcore.dll, wbemprox.dll, windeployetw.dll, wmiutils.dll
amd64_microsoft-windows-i..edia-legacy-windows_31bf3856ad364e35 [10.0.22621.2506] -> acmigration.dll
amd64_microsoft-windows-i..edia-legacy-xmllite_31bf3856ad364e35 [10.0.22621.2506] -> xmllite.dll
amd64_microsoft-windows-i..ell-serviceprovider_31bf3856ad364e35 [10.0.22621.2506] -> windows.immersiveshell.serviceprovider.dll
amd64_microsoft-windows-i..ersandsecurityzones_31bf3856ad364e35 [11.0.22621.2506] -> urlmon.dll
amd64_microsoft-windows-i..hancementmanagement_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.graphics.display.displayenhancementmanagement.dll
amd64_microsoft-windows-i..hardwareconfirmator_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.hardwareconfirmator.dll
amd64_microsoft-windows-i..henticationbinaries_31bf3856ad364e35 [10.0.22621.2506] -> authmap.dll
amd64_microsoft-windows-i..hinese-imepadapplet_31bf3856ad364e35 [10.0.22621.2506] -> imtccac.dll, imtcdic.dll, imtcskf.dll
amd64_microsoft-windows-i..i_initiator_service_31bf3856ad364e35 [10.0.22621.2506] -> iscsicli.exe, iscsidsc.dll, iscsied.dll, iscsiexe.dll, iscsium.dll, iscsiwmi.dll, iscsiwmiv2.dll
amd64_microsoft-windows-i..iextensionsbinaries_31bf3856ad364e35 [10.0.22621.2506] -> isapi.dll
amd64_microsoft-windows-i..l-devices-bluetooth_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.devices.bluetooth.dll
amd64_microsoft-windows-i..l-xamlinputviewhost_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.shell.xamlinputviewhost.dll
amd64_microsoft-windows-i..lays-classextension_31bf3856ad364e35 [10.0.22621.2506] -> iddcx.dll
amd64_microsoft-windows-i..ldhangul-tipprofile_31bf3856ad364e35 [10.0.22621.2506] -> imkrotip.dll
amd64_microsoft-windows-i..lineid-wamextension_31bf3856ad364e35 [10.0.22621.2506] -> microsoftaccountwamextension.dll
amd64_microsoft-windows-i..loudid-wxhextension_31bf3856ad364e35 [10.0.22621.2506] -> cloudidwxhextension.dll
amd64_microsoft-windows-i..nal-core-locale-nls_31bf3856ad364e35 [10.0.22621.2506] -> winnlsres.dll
amd64_microsoft-windows-i..nearshareexperience_31bf3856ad364e35 [10.0.22621.2506] -> microsoft-windows-internal-shell-nearshareexperience.dll
amd64_microsoft-windows-i..nese-core-essential_31bf3856ad364e35 [10.0.22621.2506] -> imtccfg.dll, imtccore.dll
amd64_microsoft-windows-i..nternetcontrolpanel_31bf3856ad364e35 [11.0.22621.2506] -> inetcpl.cpl
amd64_microsoft-windows-i..ntrolpanel.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> systemsettings.exe
amd64_microsoft-windows-i..oexistencemigration_31bf3856ad364e35 [10.0.22621.2506] -> iphlpsvc.dll
amd64_microsoft-windows-i..on-aad-wamextension_31bf3856ad364e35 [10.0.22621.2506] -> aadwamextension.dll
amd64_microsoft-windows-i..ore-shareexperience_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.shellcommon.shareexperience.dll
amd64_microsoft-windows-i..p-media-legacy-base_31bf3856ad364e35 [10.0.22621.2506] -> actionqueue.dll, auditetw.dll, cmi2migxml.dll, cmisetupetw.dll, csiagent.dll, dpx.dll, hwcompat.dll, itgtupg.dll, migcore.dll, mighost.exe, migisol.dll, migres.dll, migstore.dll, migtestplugin.dll, msdelta.dll, mspatcha.dll, mxeagent.dll, setupcletw.dll, smiengine.dll, upgradeagent.dll, wdsupgcompl.dll, winsetupetw.dll
amd64_microsoft-windows-i..playcolormanagement_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.graphics.display.displaycolormanagement.dll
amd64_microsoft-windows-i..pturepicker-desktop_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.capturepicker.desktop.dll
amd64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35 [10.0.22621.2506] -> ahadmin.dll, appcmd.exe, appobj.dll, cngkeyhelper.dll, iisres.dll, iisrtl.dll, iissetup.exe, iissyspr.dll, iisutil.dll, nativerd.dll, rsca.dll, rscaext.dll, w3ctrlps.dll
amd64_microsoft-windows-i..rewebenginebinaries_31bf3856ad364e35 [10.0.22621.2506] -> hwebcore.dll, iiscore.dll, w3dt.dll
amd64_microsoft-windows-i..rnational-timezones_31bf3856ad364e35 [10.0.22621.2506] -> tzres.dll
amd64_microsoft-windows-i..sedsetup-media-base_31bf3856ad364e35 [10.0.22621.2506] -> autorun.dll, cmisetup.dll, diagnostic.dll, pnpibs.dll, rollback.exe, setup.exe, smiengine.dll, spflvrnt.dll, spprgrss.dll, spwizeng.dll, upgloader.dll, uxlib.dll, uxlibres.dll, w32uiimg.dll, wdsclient.dll, win32ui.dll, winsetup.dll
amd64_microsoft-windows-i..setup-media-onecore_31bf3856ad364e35 [10.0.22621.2715] * -> dism.exe, imagelib.dll, testplugin.dll
amd64_microsoft-windows-i..setup-media-windows_31bf3856ad364e35 [10.0.22621.2506] -> input.dll, sqmapi.dll
amd64_microsoft-windows-i..setup-media-xmllite_31bf3856ad364e35 [10.0.22621.2506] -> xmllite.dll
amd64_microsoft-windows-i..switch-toasthandler_31bf3856ad364e35 [10.0.22621.2506] -> inputswitchtoasthandler.exe
amd64_microsoft-windows-i..taskflow-dataengine_31bf3856ad364e35 [10.0.22621.2506] -> taskflowdataengine.dll
amd64_microsoft-windows-i..tional-chinese-core_31bf3856ad364e35 [10.0.22621.2506] -> imtclnwz.exe, imtcprop.exe, imtctrln.dll
amd64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35 [11.0.22621.2506] -> indexeddblegacy.dll, mshtml.dll
amd64_microsoft-windows-i..tocolimplementation_31bf3856ad364e35 [11.0.22621.2506] -> jsproxy.dll, wininet.dll
amd64_microsoft-windows-i..tup-media-legacy-ds_31bf3856ad364e35 [10.0.22621.2506] -> ntdsupg.dll, ntfrsupg.dll, rmsupg.dll
amd64_microsoft-windows-icm-base_31bf3856ad364e35 [10.0.22621.2506] -> icm32.dll, mscms.dll
amd64_microsoft-windows-idctrls_31bf3856ad364e35 [10.0.22621.2506] -> idctrls.dll
amd64_microsoft-windows-ie-antiphishfilter_31bf3856ad364e35 [11.0.22621.2506] -> ieapfltr.dll
amd64_microsoft-windows-ie-behaviors_31bf3856ad364e35 [11.0.22621.2506] -> iepeers.dll
amd64_microsoft-windows-ie-directxtransforms_31bf3856ad364e35 [11.0.22621.2506] -> dxtmsft.dll, dxtrans.dll
amd64_microsoft-windows-ie-htmlapplication_31bf3856ad364e35 [11.0.22621.2506] -> mshta.exe
amd64_microsoft-windows-ie-htmlrendering_31bf3856ad364e35 [11.0.22621.2715] * -> edgehtml.dll, edgemanager.dll, webplatstorageserver.dll
amd64_microsoft-windows-ie-iediag_31bf3856ad364e35 [11.0.22621.2506] -> iediagcmd.exe
amd64_microsoft-windows-ie-ieproxy_31bf3856ad364e35 [11.0.22621.2506] -> ieproxy.dll
amd64_microsoft-windows-ie-ieshims_31bf3856ad364e35 [11.0.22621.2506] -> ieshims.dll
amd64_microsoft-windows-ie-mshtmldac_31bf3856ad364e35 [11.0.22621.2506] -> mshtmldac.dll
amd64_microsoft-windows-ie-runtimeutilities_31bf3856ad364e35 [11.0.22621.2506] -> edgeiso.dll, iertutil.dll, msiso.dll
amd64_microsoft-windows-ie-setup-support_31bf3856ad364e35 [11.0.22621.2506] -> ie4uinit.exe, ie4ushowie.exe, iernonce.dll, iesetup.dll
amd64_microsoft-windows-ie-vgx_31bf3856ad364e35 [11.0.22621.2506] -> vgx.dll
amd64_microsoft-windows-ieframe_31bf3856ad364e35 [11.0.22621.2506] -> ieframe.dll, iemigplugin.dll, iesettingsync.exe
amd64_microsoft-windows-iis-httpcachebinaries_31bf3856ad364e35 [10.0.22621.2506] -> cachhttp.dll
amd64_microsoft-windows-imagelib_31bf3856ad364e35 [10.0.22621.2715] * -> imagelib.dll
amd64_microsoft-windows-imageres-embedded_31bf3856ad364e35 [10.0.22621.2506] -> imageres.dll
amd64_microsoft-windows-imageres_31bf3856ad364e35 [10.0.22621.2506] -> imageres.dll
amd64_microsoft-windows-imapiv2-legacyshim_31bf3856ad364e35 [10.0.22621.2506] -> imapi.dll
amd64_microsoft-windows-ime-eashared-ccshared_31bf3856ad364e35 [10.0.22621.2506] -> imccphr.exe, imedicapiccps.dll
amd64_microsoft-windows-ime-korean-cacpad_31bf3856ad364e35 [10.0.22621.2506] -> imkrcac.dll
amd64_microsoft-windows-ime-korean-commonapi_31bf3856ad364e35 [10.0.22621.2506] -> imkrapi.dll
amd64_microsoft-windows-ime-korean-hanjadic_31bf3856ad364e35 [10.0.22621.2506] -> imkrhjd.dll
amd64_microsoft-windows-ime-korean-padresource_31bf3856ad364e35 [10.0.22621.2506] -> padrs412.dll
amd64_microsoft-windows-ime-korean-skfpad_31bf3856ad364e35 [10.0.22621.2506] -> imkrskf.dll
amd64_microsoft-windows-ime-korean-tipprofile_31bf3856ad364e35 [10.0.22621.2506] -> imkrtip.dll
amd64_microsoft-windows-ime-korean-tools_31bf3856ad364e35 [10.0.22621.2506] -> imkrudt.dll
amd64_microsoft-windows-imm32_31bf3856ad364e35 [10.0.22621.2506] -> imm32.dll
amd64_microsoft-windows-inputapp.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> windowsinternal.composableshell.experiences.textinput.inputapp.exe
amd64_microsoft-windows-inputprocessors_31bf3856ad364e35 [10.0.22621.2506] -> advancedemojids.dll, chsstrokeds.dll, chtbopomofods.dll, chtcangjieds.dll, chthkstrokeds.dll, chtquickds.dll, chxapds.dll, chxdecoder.dll, chxhapds.dll, chxinputrouter.dll, chxranker.dll, emojids.dll, fluencyds.dll, hashtagds.dll, ihds.dll, jpndecoder.dll, jpninputrouter.dll, jpnranker.dll, mtfappserviceds.dll, mtfdecoder.dll, mtffuzzyds.dll, mtfspellcheckds.dll, rulebasedds.dll, transliterationranker.dll, trie.dll, vocabroaminghandler.dll
amd64_microsoft-windows-inputservice_31bf3856ad364e35 [10.0.22621.2506] -> editbuffertesthook.dll, inputlocalemanager.dll, inputservice.dll, textinputmethodformatter.dll, windows.ui.core.textinput.dll, wordbreakers.dll
amd64_microsoft-windows-inputswitch_31bf3856ad364e35 [10.0.22621.2506] -> inputswitch.dll
amd64_microsoft-windows-installer-engine_31bf3856ad364e35 [10.0.22621.2506] -> msi.dll, msimsg.dll
amd64_microsoft-windows-installer-sip_31bf3856ad364e35 [10.0.22621.2506] -> msisip.dll
amd64_microsoft-windows-internal-openwithhost_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.openwithhost.dll
amd64_microsoft-windows-internal-shell-broker_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.shell.broker.dll
amd64_microsoft-windows-internal-shellcommon_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.shellcommon.dll
amd64_microsoft-windows-internal-taskbar_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.taskbar.dll
amd64_microsoft-windows-internal-ui-dialogs_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.ui.dialogs.dll
amd64_microsoft-windows-international-nlsbuild_31bf3856ad364e35 [10.0.22621.2506] -> nlsbres.dll
amd64_microsoft-windows-international-unattend_31bf3856ad364e35 [10.0.22621.2506] -> muiunattend.exe
amd64_microsoft-windows-intl_31bf3856ad364e35 [10.0.22621.2506] -> intl.cpl
amd64_microsoft-windows-ipconfig_31bf3856ad364e35 [10.0.22621.2506] -> ipconfig.exe
amd64_microsoft-windows-ipnat_31bf3856ad364e35 [10.0.22621.2506] -> ipnat.sys
amd64_microsoft-windows-ippcommon_31bf3856ad364e35 [10.0.22621.2506] -> ippcommon.dll
amd64_microsoft-windows-ippcommonproxy_31bf3856ad364e35 [10.0.22621.2506] -> ippcommonproxy.dll
amd64_microsoft-windows-iuilp_31bf3856ad364e35 [10.0.22621.2506] -> iuilp.dll
amd64_microsoft-windows-k..er-events-container_31bf3856ad364e35 [10.0.22621.2506] -> microsoft-windows-kernel-processor-power-events.dll
amd64_microsoft-windows-kdcpw_31bf3856ad364e35 [10.0.22621.2506] -> kdcpw.dll
amd64_microsoft-windows-kdscli-dll_31bf3856ad364e35 [10.0.22621.2506] -> kdscli.dll
amd64_microsoft-windows-kernel-appcore_31bf3856ad364e35 [10.0.22621.2715] * -> kernel.appcore.dll
amd64_microsoft-windows-kernel32_31bf3856ad364e35 [10.0.22621.2506] -> kernel32.dll
amd64_microsoft-windows-kernelbase_31bf3856ad364e35 [10.0.22621.2715] * -> kernelbase.dll
amd64_microsoft-windows-kernelstreaming_31bf3856ad364e35 [10.0.22621.2506] -> ks.sys, mskssrv.sys
amd64_microsoft-windows-keymgr_31bf3856ad364e35 [10.0.22621.2506] -> keymgr.dll
amd64_microsoft-windows-l..-security-processor_31bf3856ad364e35 [10.0.22621.2506] -> clipsp.sys
amd64_microsoft-windows-l..componentsinstaller_31bf3856ad364e35 [10.0.22621.2506] -> languagecomponentsinstaller.dll
amd64_microsoft-windows-l..erdiscoveryprotocol_31bf3856ad364e35 [10.0.22621.2506] -> mslldp.sys
amd64_microsoft-windows-l..ncontroller-library_31bf3856ad364e35 [10.0.22621.2506] -> logoncontroller.dll
amd64_microsoft-windows-l..nstaller-comhandler_31bf3856ad364e35 [10.0.22621.2506] -> languagecomponentsinstallercomhandler.exe
amd64_microsoft-windows-l..st-abovelockapphost_31bf3856ad364e35 [10.0.22621.2506] -> abovelockapphost.dll
amd64_microsoft-windows-l2bridge-filter-driver_31bf3856ad364e35 [10.0.22621.2506] -> l2bridge.sys
amd64_microsoft-windows-languagesdb-onecore_31bf3856ad364e35 [10.0.22621.2506] -> globinputhost.dll, userlanguageprofilecallback.dll, winlangdb.dll
amd64_microsoft-windows-laps-csp_31bf3856ad364e35 [10.0.22621.2506] -> lapscsp.dll
amd64_microsoft-windows-laps-powershell_31bf3856ad364e35 [10.0.22621.2506] -> lapspsh.dll, lapsutil.dll
amd64_microsoft-windows-laps-server_31bf3856ad364e35 [10.0.22621.2506] -> laps.dll
amd64_microsoft-windows-ldap-client_31bf3856ad364e35 [10.0.22621.2506] -> wldap32.dll
amd64_microsoft-windows-lddmcore_31bf3856ad364e35 [10.0.22621.2506] -> cdd.dll, dxgkrnl.sys, dxgmms1.sys, dxgmms2.sys
amd64_microsoft-windows-legacysystemsettings_31bf3856ad364e35 [10.0.22621.2506] -> legacysystemsettings.dll
amd64_microsoft-windows-legacytaskmanager_31bf3856ad364e35 [10.0.22621.2506] -> taskmgr.exe
amd64_microsoft-windows-livecaptionsstub_31bf3856ad364e35 [10.0.22621.2506] -> livecaptions.exe
amd64_microsoft-windows-lock-controller_31bf3856ad364e35 [10.0.22621.2506] -> lockcontroller.dll
amd64_microsoft-windows-lockapp.appxmain_31bf3856ad364e35 [10.0.22621.2715] * -> lockapp.exe, locksearchapi.dll
amd64_microsoft-windows-lockappbroker-winrt_31bf3856ad364e35 [10.0.22621.2506] -> lockappbroker.dll
amd64_microsoft-windows-lockapphost_31bf3856ad364e35 [10.0.22621.2506] -> lockapphost.exe
amd64_microsoft-windows-lockscreendata_31bf3856ad364e35 [10.0.22621.2506] -> lockscreendata.dll
amd64_microsoft-windows-lsa-minwin-kernel_31bf3856ad364e35 [10.0.22621.2506] -> ksecdd.sys
amd64_microsoft-windows-lsa-minwin_31bf3856ad364e35 [10.0.22621.2506] -> lsass.exe, sspicli.dll, sspisrv.dll
amd64_microsoft-windows-lsa_31bf3856ad364e35 [10.0.22621.2506] -> ksecpkg.sys, lsaadt.dll, lsasrv.dll, offlinelsa.dll
amd64_microsoft-windows-lua-filevirtualization_31bf3856ad364e35 [10.0.22621.2506] -> luafv.sys
amd64_microsoft-windows-lua-onecore_31bf3856ad364e35 [10.0.22621.2506] -> appinfo.dll
amd64_microsoft-windows-lua_31bf3856ad364e35 [10.0.22621.2506] -> appinfoext.dll, consent.exe
amd64_microsoft-windows-lxcore_31bf3856ad364e35 [10.0.22621.2506] -> lxcore.sys
amd64_microsoft-windows-lxss-bash_31bf3856ad364e35 [10.0.22621.2506] -> bash.exe
amd64_microsoft-windows-lxss-manager_31bf3856ad364e35 [10.0.22621.2506] -> lxssmanager.dll, lxssmanagerproxystub.dll
amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35 [10.0.22621.2506] -> wsl.exe
amd64_microsoft-windows-lxss-wslapi_31bf3856ad364e35 [10.0.22621.2506] -> wslapi.dll
amd64_microsoft-windows-lxss-wslclient_31bf3856ad364e35 [10.0.22621.2506] -> wslclient.dll
amd64_microsoft-windows-lxss-wslconfig_31bf3856ad364e35 [10.0.22621.2506] -> wslconfig.exe
amd64_microsoft-windows-lxss-wslg_31bf3856ad364e35 [10.0.22621.2506] -> wslg.exe
amd64_microsoft-windows-lxss-wslhost_31bf3856ad364e35 [10.0.22621.2506] -> wslhost.exe
amd64_microsoft-windows-m..-activesyncprovider_31bf3856ad364e35 [10.0.22621.2506] -> activesyncprovider.dll
amd64_microsoft-windows-m..-management-console_31bf3856ad364e35 [10.0.22621.2506] -> cic.dll, mmc.exe, mmcbase.dll, mmcshext.dll
amd64_microsoft-windows-m..ation-mfmediaengine_31bf3856ad364e35 [10.0.22621.2506] -> mfmediaengine.dll
amd64_microsoft-windows-m..ation-mfphotography_31bf3856ad364e35 [10.0.22621.2506] -> msphotography.dll
amd64_microsoft-windows-m..band-experience-api_31bf3856ad364e35 [10.0.22621.2506] -> mbaeapipublic.dll
amd64_microsoft-windows-m..c-drivermanager-dll_31bf3856ad364e35 [10.0.22621.2506] -> odbc32.dll
amd64_microsoft-windows-m..cess-control-driver_31bf3856ad364e35 [10.0.22621.2506] -> mqac.sys
amd64_microsoft-windows-m..commonresource-core_31bf3856ad364e35 [10.0.22621.2506] -> mqutil.dll
amd64_microsoft-windows-m..count-profilenotify_31bf3856ad364e35 [10.0.22621.2506] -> msaprofilenotificationhandler.dll
amd64_microsoft-windows-m..d-experience-smsapi_31bf3856ad364e35 [10.0.22621.2506] -> mbsmsapi.dll
amd64_microsoft-windows-m..elmanifests-windows_31bf3856ad364e35 [10.0.22621.2506] -> chxmig.dll, imjpmig.dll, imkrmig.dll, msctfmig.dll, tabletextservicemig.dll
amd64_microsoft-windows-m..ents-mdac-oledb-dll_31bf3856ad364e35 [10.0.22621.2506] -> oledb32.dll
amd64_microsoft-windows-m..ervice-winrt-client_31bf3856ad364e35 [10.0.22621.2506] -> autopilot.dll, windows.management.enrollmentstatustracking.configprovider.dll, windows.management.inprocobjects.dll, windows.management.moderndeployment.configproviders.dll, windows.management.service.dll
amd64_microsoft-windows-m..essagingcoreservice_31bf3856ad364e35 [10.0.22621.2506] -> mqbkup.exe, mqsvc.exe
amd64_microsoft-windows-m..ftaccount-extension_31bf3856ad364e35 [10.0.22621.2506] -> microsoftaccountextension.dll
amd64_microsoft-windows-m..ge-capture-pipeline_31bf3856ad364e35 [10.0.22621.2506] -> mixedrealitycapture.pipeline.dll, mixedrealitycapture.proxystub.dll
amd64_microsoft-windows-m..ifests-onecoreadmin_31bf3856ad364e35 [10.0.22621.2506] -> wmimigrationplugin.dll
amd64_microsoft-windows-m..iv2-dmwmibridgeshub_31bf3856ad364e35 [10.0.22621.2506] -> dmwmibridgeprovshub.dll
amd64_microsoft-windows-m..loyment-diagnostics_31bf3856ad364e35 [10.0.22621.2506] -> autopilotdiag.dll
amd64_microsoft-windows-m..mentmanifests-shell_31bf3856ad364e35 [10.0.22621.2506] -> shmig.dll
amd64_microsoft-windows-m..n-frameserverclient_31bf3856ad364e35 [10.0.22621.2506] -> frameserverclient.dll, mfsensorgroup.dll
amd64_microsoft-windows-m..ndation-frameserver_31bf3856ad364e35 [10.0.22621.2506] -> frameserver.dll, frameservermonitor.dll, fsiso.exe
amd64_microsoft-windows-m..nents-mdac-msdadiag_31bf3856ad364e35 [10.0.22621.2506] -> msdadiag.dll
amd64_microsoft-windows-m..ng-messagingservice_31bf3856ad364e35 [10.0.22621.2506] -> messagingservice.dll
amd64_microsoft-windows-m..nt-browser.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.diagnostics.tracing.eventsource.dll, secureassessment_jsbridge.dll, secureassessmentbrowser.exe, winrtadapter.dll
amd64_microsoft-windows-m..pickerhost.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> modalsharepickerhost.exe, sharepickerui.dll
amd64_microsoft-windows-m..pointmanager-minwin_31bf3856ad364e35 [10.0.22621.2506] -> mountmgr.sys
amd64_microsoft-windows-m..qlserver-driver-dll_31bf3856ad364e35 [10.0.22621.2506] -> sqlsrv32.dll
amd64_microsoft-windows-m..reassessment-config_31bf3856ad364e35 [10.0.22621.2506] -> secureassessmenthandlers.dll, windows.management.secureassessment.cfgprovider.dll
amd64_microsoft-windows-m..rience-api-internal_31bf3856ad364e35 [10.0.22621.2506] -> mbaeapi.dll
amd64_microsoft-windows-m..server-provider-dll_31bf3856ad364e35 [10.0.22621.2715] * -> sqloledb.dll
amd64_microsoft-windows-m..servermonitorclient_31bf3856ad364e35 [10.0.22621.2506] -> frameservermonitorclient.dll
amd64_microsoft-windows-magnify_31bf3856ad364e35 [10.0.22621.2506] -> magnify.exe
amd64_microsoft-windows-mapcontrol_31bf3856ad364e35 [10.0.22621.2506] -> bingmaps.dll, bingonlineservices.dll, jpmapcontrol.dll, mapconfiguration.dll, mapcontrolcore.dll, mapcontrolstringsres.dll, mapgeocoder.dll, maprouter.dll, mapsbtsvc.dll, mapsbtsvcproxy.dll, mapscsp.dll, mapsstore.dll, mapstoasttask.dll, mapsupdatetask.dll, microsoft-windows-mapcontrols.dll, microsoft-windows-moshost.dll, moshost.dll, moshostclient.dll, moshostcore.dll, mosstorage.dll, nmadirect.dll, ztrace_maps.dll
amd64_microsoft-windows-mapi-mmga_31bf3856ad364e35 [10.0.22621.2506] -> mmgaclient.dll, mmgaproxystub.dll, mmgaserver.exe
amd64_microsoft-windows-mapi_31bf3856ad364e35 [10.0.22621.2506] -> fixmapi.exe, mapi32.dll, mapistub.dll
amd64_microsoft-windows-mbb-classextension_31bf3856ad364e35 [10.0.22621.2506] -> mbbcx.sys
amd64_microsoft-windows-mccs-synccontroller_31bf3856ad364e35 [10.0.22621.2506] -> synccontroller.dll
amd64_microsoft-windows-mcpmanagement_31bf3856ad364e35 [10.0.22621.2506] -> mcpmanagementproxy.dll, mcpmanagementservice.dll
amd64_microsoft-windows-mcrecvsrc_31bf3856ad364e35 [10.0.22621.2506] -> mcrecvsrc.dll
amd64_microsoft-windows-mdm-wmiv2-dmwmibridge_31bf3856ad364e35 [10.0.22621.2506] -> dmwmibridgeprov.dll, dmwmibridgeprov1.dll
amd64_microsoft-windows-mdmagent_31bf3856ad364e35 [10.0.22621.2506] -> mdmagent.exe
amd64_microsoft-windows-mdmappinstaller_31bf3856ad364e35 [10.0.22621.2506] -> mdmappinstaller.exe
amd64_microsoft-windows-mdmregistration2_31bf3856ad364e35 [10.0.22621.2506] -> mdmregistration.dll
amd64_microsoft-windows-media-audio_31bf3856ad364e35 [10.0.22621.2715] * -> windows.media.audio.dll
amd64_microsoft-windows-media-devices_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.devices.dll
amd64_microsoft-windows-media-import-api_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.import.dll
amd64_microsoft-windows-media-streaming-dll_31bf3856ad364e35 [10.0.22621.2715] * -> windows.media.streaming.dll
amd64_microsoft-windows-mediafoundation-mfsvr_31bf3856ad364e35 [10.0.22621.2506] -> mfsvr.dll
amd64_microsoft-windows-mediafoundation_31bf3856ad364e35 [10.0.22621.2715] * -> mf.dll, mfpmp.exe
amd64_microsoft-windows-mediaplayer-core_31bf3856ad364e35 [10.0.22621.2506] -> dxmasf.dll, msdxm.ocx, spwmp.dll, wmp.dll, wmpconfig.exe, wmplayer.exe, wmploc.dll, wmpshare.exe
amd64_microsoft-windows-mediaplayer-wmpeffects_31bf3856ad364e35 [10.0.22621.2506] -> wmpeffects.dll
amd64_microsoft-windows-mediaplayer-wmvcore_31bf3856ad364e35 [10.0.22621.2506] -> wmvcore.dll
amd64_microsoft-windows-mfasfsrcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfasfsrcsnk.dll
amd64_microsoft-windows-mfaudiocnv_31bf3856ad364e35 [10.0.22621.2506] -> mfaudiocnv.dll
amd64_microsoft-windows-mfcore_31bf3856ad364e35 [10.0.22621.2715] * -> mfcore.dll, mfps.dll
amd64_microsoft-windows-mfds_31bf3856ad364e35 [10.0.22621.2506] -> mfds.dll
amd64_microsoft-windows-mfmkvsrcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfmkvsrcsnk.dll
amd64_microsoft-windows-mfmp4srcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfmp4srcsnk.dll
amd64_microsoft-windows-mfmpeg2srcsnk_31bf3856ad364e35 [10.0.22621.2715] * -> mfmpeg2srcsnk.dll
amd64_microsoft-windows-mfnetsrc_31bf3856ad364e35 [10.0.22621.2506] -> mfnetsrc.dll
amd64_microsoft-windows-mfplat_31bf3856ad364e35 [10.0.22621.2506] -> mfplat.dll
amd64_microsoft-windows-mfplay_31bf3856ad364e35 [10.0.22621.2506] -> mfplay.dll
amd64_microsoft-windows-mfreadwrite_31bf3856ad364e35 [10.0.22621.2506] -> mfreadwrite.dll
amd64_microsoft-windows-mfsrcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfsrcsnk.dll
amd64_microsoft-windows-migrationengine_31bf3856ad364e35 [10.0.22621.2506] -> cmi2migxml.dll, csiagent.dll, migcore.dll, mighost.exe, migres.dll, migstore.dll, mxeagent.dll
amd64_microsoft-windows-minshellext_31bf3856ad364e35 [10.0.22621.2506] -> minshellext.dll
amd64_microsoft-windows-miracast-receiver-api_31bf3856ad364e35 [10.0.22621.2506] -> miracastreceiver.dll
amd64_microsoft-windows-miracast-receiver-ext_31bf3856ad364e35 [10.0.22621.2506] -> miracastreceiverext.dll
amd64_microsoft-windows-mirage_31bf3856ad364e35 [10.0.22621.2506] -> windows.mirage.dll, windows.mirage.internal.dll
amd64_microsoft-windows-mitigation-client_31bf3856ad364e35 [10.0.22621.2506] -> mitigationclient.dll
amd64_microsoft-windows-mixedreality-broker_31bf3856ad364e35 [10.0.22621.2506] -> mixedreality.broker.dll
amd64_microsoft-windows-mmcss_31bf3856ad364e35 [10.0.22621.2506] -> avrt.dll, mmcss.sys
amd64_microsoft-windows-mmdeviceapi_31bf3856ad364e35 [10.0.22621.2506] -> mmdevapi.dll
amd64_microsoft-windows-mmsys_31bf3856ad364e35 [10.0.22621.2506] -> mmsys.cpl
amd64_microsoft-windows-mobilepc-location-api_31bf3856ad364e35 [10.0.22621.2506] -> locationapi.dll
amd64_microsoft-windows-mobilepc-sensors-api_31bf3856ad364e35 [10.0.22621.2506] -> sensorsapi.dll
amd64_microsoft-windows-mobsync_31bf3856ad364e35 [10.0.22621.2506] -> synccenter.dll
amd64_microsoft-windows-modernexecserver_31bf3856ad364e35 [10.0.22621.2506] -> modernexecserver.dll
amd64_microsoft-windows-mp3dmod_31bf3856ad364e35 [10.0.22621.2506] -> mp3dmod.dll
amd64_microsoft-windows-msaatext_31bf3856ad364e35 [10.0.22621.2506] -> msaatext.dll
amd64_microsoft-windows-msac3enc_31bf3856ad364e35 [10.0.22621.2506] -> msac3enc.dll
amd64_microsoft-windows-msasn1_31bf3856ad364e35 [10.0.22621.2506] -> msasn1.dll
amd64_microsoft-windows-msauddecmft_31bf3856ad364e35 [10.0.22621.2506] -> msauddecmft.dll
amd64_microsoft-windows-msauditevtlog_31bf3856ad364e35 [10.0.22621.2506] -> adtschema.dll, msaudite.dll, msobjs.dll
amd64_microsoft-windows-msconfig-exe_31bf3856ad364e35 [10.0.22621.2506] -> msconfig.exe
amd64_microsoft-windows-msdt_31bf3856ad364e35 [10.0.22621.2506] -> msdt.exe
amd64_microsoft-windows-msfs_31bf3856ad364e35 [10.0.22621.2506] -> msfs.sys
amd64_microsoft-windows-msftedit_31bf3856ad364e35 [10.0.22621.2506] -> msftedit.dll
amd64_microsoft-windows-msieftp_31bf3856ad364e35 [10.0.22621.2506] -> msieftp.dll
amd64_microsoft-windows-msinfo32-exe-common_31bf3856ad364e35 [10.0.22621.2506] -> msinfo32.exe
amd64_microsoft-windows-msinfo32-exe_31bf3856ad364e35 [10.0.22621.2506] -> msinfo32.exe
amd64_microsoft-windows-mskeyprotcli-dll_31bf3856ad364e35 [10.0.22621.2506] -> mskeyprotcli.dll
amd64_microsoft-windows-mskeyprotect-dll_31bf3856ad364e35 [10.0.22621.2506] -> mskeyprotect.dll
amd64_microsoft-windows-msmpeg2adec_31bf3856ad364e35 [10.0.22621.2506] -> msmpeg2adec.dll
amd64_microsoft-windows-msmpeg2enc_31bf3856ad364e35 [10.0.22621.2506] -> msmpeg2enc.dll
amd64_microsoft-windows-msmpeg2vdec_31bf3856ad364e35 [10.0.22621.2715] * -> msmpeg2vdec.dll
amd64_microsoft-windows-msmq-admin_31bf3856ad364e35 [10.0.22621.2506] -> mqcertui.dll, mqsnap.dll
amd64_microsoft-windows-msmq-installer_31bf3856ad364e35 [10.0.22621.2506] -> mqad.dll, mqcmiplugin.dll, mqmigplugin.dll, mqsec.dll
amd64_microsoft-windows-msmq-powershell_31bf3856ad364e35 [10.0.22621.2715] * -> microsoft.msmq.activex.interop.dll, microsoft.msmq.powershell.commands.dll, microsoft.msmq.runtime.interop.dll
amd64_microsoft-windows-msmq-queuemanager-core_31bf3856ad364e35 [10.0.22621.2506] -> mqqm.dll
amd64_microsoft-windows-msmq-runtime-core_31bf3856ad364e35 [10.0.22621.2506] -> mqrt.dll
amd64_microsoft-windows-msmq-runtime_31bf3856ad364e35 [10.0.22621.2506] -> mqoa.dll
amd64_microsoft-windows-mspaint_31bf3856ad364e35 [10.0.22621.2506] -> mspaint.exe
amd64_microsoft-windows-mssign32-dll_31bf3856ad364e35 [10.0.22621.2506] -> mssign32.dll
amd64_microsoft-windows-msvcrt_31bf3856ad364e35 [10.0.22621.2506] -> msvcrt.dll
amd64_microsoft-windows-msvideodsp_31bf3856ad364e35 [10.0.22621.2506] -> msvideodsp.dll
amd64_microsoft-windows-msxml30_31bf3856ad364e35 [10.0.22621.2506] -> msxml3.dll, msxml3r.dll
amd64_microsoft-windows-msxml60_31bf3856ad364e35 [10.0.22621.2506] -> msxml6.dll, msxml6r.dll
amd64_microsoft-windows-mtf-cht-extra_31bf3856ad364e35 [10.0.22621.2506] -> chtadvancedds.dll
amd64_microsoft-windows-mtf-contactharvesterds_31bf3856ad364e35 [10.0.22621.2506] -> contactharvesterds.dll
amd64_microsoft-windows-mtf-jpn-datasources_31bf3856ad364e35 [10.0.22621.2506] -> bingasds.dll, bingfilterds.dll, ddds.dll, filterds.dll, jpnserviceds.dll, sdds.dll
amd64_microsoft-windows-mtf-kor-datasources_31bf3856ad364e35 [10.0.22621.2506] -> hanjads.dll
amd64_microsoft-windows-mtf_31bf3856ad364e35 [10.0.22621.2506] -> mtf.dll
amd64_microsoft-windows-mtfserver_31bf3856ad364e35 [10.0.22621.2506] -> mtfserver.dll
amd64_microsoft-windows-mup_31bf3856ad364e35 [10.0.22621.2506] -> mup.sys, mupmigplugin.dll
amd64_microsoft-windows-n.._service_runtimeapi_31bf3856ad364e35 [10.0.22621.2506] -> iashlpr.dll
amd64_microsoft-windows-n..agerdesktopprovider_31bf3856ad364e35 [10.0.22621.2506] -> npsmdesktopprovider.dll
amd64_microsoft-windows-n..apter-flight-driver_31bf3856ad364e35 [10.0.22621.2506] -> rteth.sys
amd64_microsoft-windows-n..ayingsessionmanager_31bf3856ad364e35 [10.0.22621.2506] -> npsm.dll
amd64_microsoft-windows-n..diagnostics-package_31bf3856ad364e35 [10.0.22621.2506] -> diagpackage.dll, networkdiagnosticsnapin.dll
amd64_microsoft-windows-n..ion_service_iassvcs_31bf3856ad364e35 [10.0.22621.2506] -> iassvcs.dll
amd64_microsoft-windows-n..ion_service_runtime_31bf3856ad364e35 [10.0.22621.2506] -> ias.dll, iasacct.dll, iaspolcy.dll, iasrad.dll
amd64_microsoft-windows-n..kux-rasmediamanager_31bf3856ad364e35 [10.0.22621.2506] -> rasmediamanager.dll
amd64_microsoft-windows-n..n_service_datastore_31bf3856ad364e35 [10.0.22621.2506] -> iasads.dll, iasdatastore.dll, iasrecst.dll, sdohlp.dll
amd64_microsoft-windows-n..ntelligenceplatform_31bf3856ad364e35 [10.0.22621.2506] -> notificationintelligenceplatform.dll
amd64_microsoft-windows-n..ork-setup-servicing_31bf3856ad364e35 [10.0.22621.2506] -> netdriverinstall.dll, netsetupapi.dll, netsetupengine.dll
amd64_microsoft-windows-n..orking-connectivity_31bf3856ad364e35 [10.0.22621.2506] -> ondemandconnroutehelper.dll, windows.networking.connectivity.dll
amd64_microsoft-windows-n..pture-wmiv2provider_31bf3856ad364e35 [10.0.22621.2506] -> neteventpacketcapture.dll, netevtfwdr.exe
amd64_microsoft-windows-n..quickstart.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> narratorquickstart.exe
amd64_microsoft-windows-n..rk-executioncontext_31bf3856ad364e35 [10.0.22621.2506] -> executioncontext.sys
amd64_microsoft-windows-n..rkux-mbmediamanager_31bf3856ad364e35 [10.0.22621.2506] -> mbmediamanager.dll
amd64_microsoft-windows-n..setup-compatibility_31bf3856ad364e35 [10.0.22621.2506] -> netcfgnotifyobjecthost.exe, netsetupshim.dll
amd64_microsoft-windows-n..sion-netprovisionsp_31bf3856ad364e35 [10.0.22621.2506] -> netprovisionsp.dll
amd64_microsoft-windows-n..thernetmediamanager_31bf3856ad364e35 [10.0.22621.2506] -> ethernetmediamanager.dll
amd64_microsoft-windows-n..tion_service_iassam_31bf3856ad364e35 [10.0.22621.2506] -> iassam.dll
amd64_microsoft-windows-n..tion_service_iassdo_31bf3856ad364e35 [10.0.22621.2506] -> iassdo.dll
amd64_microsoft-windows-n..tion_service_rassfm_31bf3856ad364e35 [10.0.22621.2506] -> rassfm.dll
amd64_microsoft-windows-n..ux-wlanmediamanager_31bf3856ad364e35 [10.0.22621.2506] -> wlanmediamanager.dll
amd64_microsoft-windows-n..wdf-class-extension_31bf3856ad364e35 [10.0.22621.2506] -> netadaptercx.sys
amd64_microsoft-windows-n..x-eaprequesthandler_31bf3856ad364e35 [10.0.22621.2506] -> windows.networking.ux.eaprequesthandler.dll
amd64_microsoft-windows-narrator_31bf3856ad364e35 [10.0.22621.2506] -> narrator.exe
amd64_microsoft-windows-native-80211_31bf3856ad364e35 [10.0.22621.2506] -> nwifi.sys, wdiwifi.sys
amd64_microsoft-windows-naturallanguage6-base_31bf3856ad364e35 [10.0.22621.2506] -> naturallanguage6.dll
amd64_microsoft-windows-navshutdown_31bf3856ad364e35 [10.0.22621.2506] -> navshutdown.dll
amd64_microsoft-windows-nbtstat_31bf3856ad364e35 [10.0.22621.2506] -> nbtstat.exe
amd64_microsoft-windows-ncrypt-dll_31bf3856ad364e35 [10.0.22621.2506] -> ncrypt.dll
amd64_microsoft-windows-ncryptprov-dll_31bf3856ad364e35 [10.0.22621.2506] -> ncryptprov.dll
amd64_microsoft-windows-ncryptsslp-dll_31bf3856ad364e35 [10.0.22621.2506] -> ncryptsslp.dll
amd64_microsoft-windows-ncsiuwpapp.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> ncsiuwpapp.exe, ncsiuwpbackgroundtasks.dll
amd64_microsoft-windows-ndis-implatform_31bf3856ad364e35 [10.0.22621.2506] -> implatsetup.dll, ndisimplatcim.dll, ndisimplatform.sys, netswitchteamcim.dll
amd64_microsoft-windows-ndis-minwin_31bf3856ad364e35 [10.0.22621.2506] -> ndis.sys
amd64_microsoft-windows-ndu_31bf3856ad364e35 [10.0.22621.2506] -> ndu.sys, nduprov.dll
amd64_microsoft-windows-net1-command-line-tool_31bf3856ad364e35 [10.0.22621.2506] -> net1.exe
amd64_microsoft-windows-netadaptercim_31bf3856ad364e35 [10.0.22621.2506] -> netadaptercim.dll
amd64_microsoft-windows-netapi32_31bf3856ad364e35 [10.0.22621.2506] -> netapi32.dll
amd64_microsoft-windows-netbios_31bf3856ad364e35 [10.0.22621.2506] -> netbios.sys
amd64_microsoft-windows-netbt-minwin_31bf3856ad364e35 [10.0.22621.2506] -> netbt.sys
amd64_microsoft-windows-netcoinstaller_31bf3856ad364e35 [10.0.22621.2506] -> nci.dll
amd64_microsoft-windows-netcorehelperclasses_31bf3856ad364e35 [10.0.22621.2506] -> netcorehc.dll
amd64_microsoft-windows-netio-infrastructure_31bf3856ad364e35 [10.0.22621.2506] -> netio.sys
amd64_microsoft-windows-netjoin_31bf3856ad364e35 [10.0.22621.2506] -> netjoin.dll
amd64_microsoft-windows-netplwiz_31bf3856ad364e35 [10.0.22621.2506] -> netplwiz.dll
amd64_microsoft-windows-netshell_31bf3856ad364e35 [10.0.22621.2506] -> ncpa.cpl, netshell.dll
amd64_microsoft-windows-netutils_31bf3856ad364e35 [10.0.22621.2506] -> netutils.dll
amd64_microsoft-windows-network-qos-pacer_31bf3856ad364e35 [10.0.22621.2506] -> pacer.sys, wshqos.dll
amd64_microsoft-windows-network-qos-wmi_31bf3856ad364e35 [10.0.22621.2506] -> qoswmi.dll
amd64_microsoft-windows-network-security-winpe_31bf3856ad364e35 [10.0.22621.2506] -> bfe.dll, fwpuclnt.dll, ikeext.dll, nshwfp.dll
amd64_microsoft-windows-network-security_31bf3856ad364e35 [10.0.22621.2506] -> bfe.dll, fwpuclnt.dll, ikeext.dll, wfplwfs.sys
amd64_microsoft-windows-network-setup_31bf3856ad364e35 [10.0.22621.2506] -> netsetupsvc.dll
amd64_microsoft-windows-networkbridge_31bf3856ad364e35 [10.0.22621.2506] -> bridge.sys, bridgemigplugin.dll, bridgeres.dll, bridgeunattend.exe
amd64_microsoft-windows-networkbridgenetsh_31bf3856ad364e35 [10.0.22621.2506] -> hnetmon.dll
amd64_microsoft-windows-networkicon_31bf3856ad364e35 [10.0.22621.2506] -> networkicon.dll
amd64_microsoft-windows-networkprofile_31bf3856ad364e35 [10.0.22621.2506] -> ncsi.dll, netprofmsvc.dll, nlaapi.dll, nlmproxy.dll, nlmsprep.dll
amd64_microsoft-windows-networktopology-inf_31bf3856ad364e35 [10.0.22621.2506] -> lltdio.sys, rspndr.sys
amd64_microsoft-windows-networktopology_31bf3856ad364e35 [10.0.22621.2506] -> lltdapi.dll, lltdres.dll, lltdsvc.dll
amd64_microsoft-windows-networkux-broker_31bf3856ad364e35 [10.0.22621.2506] -> networkuxbroker.dll
amd64_microsoft-windows-networkux-legacyux_31bf3856ad364e35 [10.0.22621.2506] -> legacynetux.dll, legacynetuxhost.exe
amd64_microsoft-windows-newdev_31bf3856ad364e35 [10.0.22621.2506] -> ndadmin.exe, newdev.dll, newdev.exe
amd64_microsoft-windows-nfc-semanagement_31bf3856ad364e35 [10.0.22621.2506] -> microsoft-windowsphone-semanagementprovider.dll, semgrsvc.dll
amd64_microsoft-windows-nfs-clientcore_31bf3856ad364e35 [10.0.22621.2506] -> nfsclnt.exe, nfsrdr.sys
amd64_microsoft-windows-nfs-openrpc_31bf3856ad364e35 [10.0.22621.2506] -> rpcxdr.sys
amd64_microsoft-windows-nlasvc-installers_31bf3856ad364e35 [10.0.22621.2506] -> nlansp_c.dll
amd64_microsoft-windows-notepad_31bf3856ad364e35 [10.0.22621.2506] -> notepad.exe
amd64_microsoft-windows-npfs_31bf3856ad364e35 [10.0.22621.2506] -> npfs.sys
amd64_microsoft-windows-ntdll_31bf3856ad364e35 [10.0.22621.2506] -> ntdll.dll
amd64_microsoft-windows-ntfs_31bf3856ad364e35 [10.0.22621.2715] * -> ntfs.sys
amd64_microsoft-windows-ntlanman_31bf3856ad364e35 [10.0.22621.2506] -> ntlanman.dll
amd64_microsoft-windows-ntshrui_31bf3856ad364e35 [10.0.22621.2506] -> ntshrui.dll
amd64_microsoft-windows-o..ectionflow.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> oobenetworkconnectionflow.exe
amd64_microsoft-windows-o..euapcommonproxystub_31bf3856ad364e35 [10.0.22621.2506] -> onecoreuapcommonproxystub.dll
amd64_microsoft-windows-o..ore-bluetooth-avctp_31bf3856ad364e35 [10.0.22621.2506] -> bthavctpsvc.dll
amd64_microsoft-windows-o..ore-bluetooth-avrcp_31bf3856ad364e35 [10.0.22621.2506] -> bthavrcp.dll, bthavrcpappsvc.dll
amd64_microsoft-windows-o..ore-systeminputhost_31bf3856ad364e35 [10.0.22621.2506] -> ism.dll
amd64_microsoft-windows-o..re-security-webauth_31bf3856ad364e35 [10.0.22621.2506] -> authbroker.dll
amd64_microsoft-windows-o..ssociationframework_31bf3856ad364e35 [10.0.22621.2506] -> das.dll, dashost.exe, deviceassociation.dll
amd64_microsoft-windows-o..tiveportal.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> oobenetworkcaptiveportal.exe
amd64_microsoft-windows-o..uap-bluetooth-audio_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.bluetooth.audio.dll
amd64_microsoft-windows-object-picker_31bf3856ad364e35 [10.0.22621.2506] -> objsel.dll
amd64_microsoft-windows-ocpupdateagent_31bf3856ad364e35 [10.0.22621.2506] -> ocpupdateagent.dll
amd64_microsoft-windows-ocsetupapi_31bf3856ad364e35 [10.0.22621.2506] -> ocsetapi.dll
amd64_microsoft-windows-offlinefiles-ui_31bf3856ad364e35 [10.0.22621.2506] -> cscui.dll
amd64_microsoft-windows-offlineregistry_31bf3856ad364e35 [10.0.22621.2506] -> offreg.dll
amd64_microsoft-windows-ole-automation_31bf3856ad364e35 [10.0.22621.2506] -> oleaut32.dll
amd64_microsoft-windows-omadmagent_31bf3856ad364e35 [10.0.22621.2506] -> omadmagent.dll
amd64_microsoft-windows-onecore-bluetooth-hfp_31bf3856ad364e35 [10.0.22621.2506] -> btagservice.dll
amd64_microsoft-windows-onecore-inputhost_31bf3856ad364e35 [10.0.22621.2506] -> inputhost.dll
amd64_microsoft-windows-onecore-ras-base-vpn_31bf3856ad364e35 [10.0.22621.2506] -> prxyqry.dll, rasapi32.dll
amd64_microsoft-windows-onecore-winrt-storage_31bf3856ad364e35 [10.0.22621.2715] * -> windows.storage.dll
amd64_microsoft-windows-onecorecommonproxystub_31bf3856ad364e35 [10.0.22621.2506] -> onecorecommonproxystub.dll
amd64_microsoft-windows-onecoreuap-raschap_31bf3856ad364e35 [10.0.22621.2506] -> eapprovp.dll, raschap.dll
amd64_microsoft-windows-onecoreuap-rastls_31bf3856ad364e35 [10.0.22621.2715] * -> rastls.dll
amd64_microsoft-windows-onecoreuap-wlansvc_31bf3856ad364e35 [10.0.22621.2506] -> wfdprov.dll, wificonfigsp.dll, wlanapi.dll, wlanhlp.dll, wlanmsm.dll, wlansec.dll, wlansvc.dll, wlansvcpal.dll
amd64_microsoft-windows-onesettings-client_31bf3856ad364e35 [10.0.22621.2506] -> onesettingsclient.dll
amd64_microsoft-windows-oobe-core-adapters_31bf3856ad364e35 [10.0.22621.2506] -> oobecoreadapters.dll
amd64_microsoft-windows-oobe-firstlogonanim_31bf3856ad364e35 [10.0.22621.2506] -> msoobefirstlogonanim.dll
amd64_microsoft-windows-oobe-machine-dui_31bf3856ad364e35 [10.0.22621.2506] -> msoobedui.dll
amd64_microsoft-windows-oobe-machine-plugins_31bf3856ad364e35 [10.0.22621.2715] * -> msoobeplugins.dll
amd64_microsoft-windows-oobe-machine_31bf3856ad364e35 [10.0.22621.2506] -> msoobe.exe
amd64_microsoft-windows-oobe-user-broker_31bf3856ad364e35 [10.0.22621.2506] -> useroobebroker.exe
amd64_microsoft-windows-oobe-user_31bf3856ad364e35 [10.0.22621.2715] * -> useroobe.dll
amd64_microsoft-windows-opencl_31bf3856ad364e35 [10.0.22621.2506] -> opencl.dll
amd64_microsoft-windows-opengl_31bf3856ad364e35 [10.0.22621.2506] -> glu32.dll, opengl32.dll
amd64_microsoft-windows-openwith_31bf3856ad364e35 [10.0.22621.2506] -> openwith.exe
amd64_microsoft-windows-os-kernel-la57_31bf3856ad364e35 [10.0.22621.2715] * -> ntkrla57.exe
amd64_microsoft-windows-os-kernel_31bf3856ad364e35 [10.0.22621.2715] * -> ntoskrnl.exe
amd64_microsoft-windows-osk_31bf3856ad364e35 [10.0.22621.2506] -> osk.exe
amd64_microsoft-windows-overlayfilter_31bf3856ad364e35 [10.0.22621.2506] -> wof.sys
amd64_microsoft-windows-p..-localprinting-core_31bf3856ad364e35 [10.0.22621.2506] -> localui.dll, usbmon.dll
amd64_microsoft-windows-p..-personalizationcsp_31bf3856ad364e35 [10.0.22621.2506] -> desktopimgdownldr.exe, personalizationcsp.dll
amd64_microsoft-windows-p..adaptiveportmonitor_31bf3856ad364e35 [10.0.22621.2506] -> apmon.dll, apmonui.dll
amd64_microsoft-windows-p..alcontrols.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> wpcuapapp.exe
amd64_microsoft-windows-p..astbannerexperience_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.platformextension.miracastbannerexperience.dll
amd64_microsoft-windows-p..cations-userservice_31bf3856ad364e35 [10.0.22621.2506] -> wpnuserservice.dll
amd64_microsoft-windows-p..documenttargetprint_31bf3856ad364e35 [10.0.22621.2506] -> xpsdocumenttargetprint.dll
amd64_microsoft-windows-p..ension-ppi-settings_31bf3856ad364e35 [10.0.22621.2506] -> ppi.settings.dll
amd64_microsoft-windows-p..estatechangehandler_31bf3856ad364e35 [10.0.22621.2506] -> packagestatechangehandler.dll
amd64_microsoft-windows-p..installerandprintui_31bf3856ad364e35 [10.0.22621.2506] -> compstui.dll, findnetprinters.dll, printui.exe, puiapi.dll, puiobj.dll
amd64_microsoft-windows-p..itorservice-desktop_31bf3856ad364e35 [10.0.22621.2506] -> wpcdesktopmonsvc.dll
amd64_microsoft-windows-p..lcontrols-webfilter_31bf3856ad364e35 [10.0.22621.2506] -> wpcwebfilter.dll
amd64_microsoft-windows-p..nfiguration-cmdline_31bf3856ad364e35 [10.0.22621.2506] -> powercfg.exe
amd64_microsoft-windows-p..ns-platform-library_31bf3856ad364e35 [10.0.22621.2506] -> wpncore.dll
amd64_microsoft-windows-p..ns-provider-library_31bf3856ad364e35 [10.0.22621.2506] -> wpnprv.dll
amd64_microsoft-windows-p..nsimulation-desktop_31bf3856ad364e35 [10.0.22621.2506] -> inputcontroller.dll, perceptionsimulationmanager.dll
amd64_microsoft-windows-p..nsimulation-service_31bf3856ad364e35 [10.0.22621.2506] -> perceptionsimulation.proxystubs.dll, perceptionsimulationservice.exe, sixdofcontrollermanager.proxystubs.dll, virtualdisplaymanager.proxystubs.dll
amd64_microsoft-windows-p..ntalcontrolsmonitor_31bf3856ad364e35 [10.0.22621.2506] -> wpcmon.exe
amd64_microsoft-windows-p..oler-core-isolation_31bf3856ad364e35 [10.0.22621.2506] -> printisolationproxy.dll, spoolss.dll
amd64_microsoft-windows-p..oler-filterpipeline_31bf3856ad364e35 [10.0.22621.2506] -> printfilterpipelineprxy.dll, printfilterpipelinesvc.exe
amd64_microsoft-windows-p..ooler-core-localspl_31bf3856ad364e35 [10.0.22621.2506] -> faxprinterinstaller.dll, localspl.dll, printercleanuptask.dll, printnotification.dll, winprint.dll
amd64_microsoft-windows-p..ooler-networkclient_31bf3856ad364e35 [10.0.22621.2506] -> win32spl.dll
amd64_microsoft-windows-p..otifications-client_31bf3856ad364e35 [10.0.22621.2506] -> wpnclient.dll
amd64_microsoft-windows-p..package-managed-api_31bf3856ad364e35 [10.0.22621.2506] -> provpackageapi.dll
amd64_microsoft-windows-p..pprinterinstallscsp_31bf3856ad364e35 [10.0.22621.2506] -> upprinterinstallscsp.dll
amd64_microsoft-windows-p..randprintui-asyncui_31bf3856ad364e35 [10.0.22621.2506] -> prnntfy.dll
amd64_microsoft-windows-p..randprintui-ntprint_31bf3856ad364e35 [10.0.22621.2506] -> ntprint.dll, ntprint.exe
amd64_microsoft-windows-p..randprintui-printui_31bf3856ad364e35 [10.0.22621.2506] -> printui.dll
amd64_microsoft-windows-p..randprintui-prnfldr_31bf3856ad364e35 [10.0.22621.2506] -> prnfldr.dll
amd64_microsoft-windows-p..rdenrollmentmanager_31bf3856ad364e35 [10.0.22621.2506] -> passwordenrollmentmanager.dll
amd64_microsoft-windows-p..riencehost.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> peopleexperiencehost.exe
amd64_microsoft-windows-p..rnetprinting-client_31bf3856ad364e35 [10.0.22621.2506] -> inetpp.dll, inetppui.dll, wpnpinst.exe
amd64_microsoft-windows-p..rtmonitor-tcpmondll_31bf3856ad364e35 [10.0.22621.2506] -> tcpmon.dll
amd64_microsoft-windows-p..s-developer-library_31bf3856ad364e35 [10.0.22621.2506] -> wpnapps.dll
amd64_microsoft-windows-p..soundservice-client_31bf3856ad364e35 [10.0.22621.2506] -> playsndsrv.dll
amd64_microsoft-windows-p..talcontrolssettings_31bf3856ad364e35 [10.0.22621.2506] -> wpc.dll
amd64_microsoft-windows-p..tifications-service_31bf3856ad364e35 [10.0.22621.2506] -> wpnservice.dll
amd64_microsoft-windows-p..ting-lprportmonitor_31bf3856ad364e35 [10.0.22621.2506] -> lpq.exe, lpr.exe, lprhelp.dll, lprmon.dll, lprmonui.dll
amd64_microsoft-windows-p..ting-spooler-client_31bf3856ad364e35 [10.0.22621.2506] -> winspool.drv
amd64_microsoft-windows-p..tioncenter.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> printqueueactioncenter.exe
amd64_microsoft-windows-p..tiondialog.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> pinningconfirmationdialog.exe
amd64_microsoft-windows-p..tionsimulationinput_31bf3856ad364e35 [10.0.22621.2506] -> perceptionsimulationinput.dll, perceptionsimulationinput.exe
amd64_microsoft-windows-p..unterinfrastructure_31bf3856ad364e35 [10.0.22621.2715] * -> cntrtextmig.dll
amd64_microsoft-windows-p9np_31bf3856ad364e35 [10.0.22621.2506] -> p9np.dll
amd64_microsoft-windows-p9rdrservice_31bf3856ad364e35 [10.0.22621.2506] -> p9rdrservice.dll
amd64_microsoft-windows-packagemanager_31bf3856ad364e35 [10.0.22621.2506] -> pkgmgr.exe, ssshim.dll
amd64_microsoft-windows-parentalcontrols-ots_31bf3856ad364e35 [10.0.22621.2506] -> approvechildrequest.exe, wpcapi.dll
amd64_microsoft-windows-partitionmanager_31bf3856ad364e35 [10.0.22621.2506] -> partmgr.sys
amd64_microsoft-windows-pcshellcommonproxystub_31bf3856ad364e35 [10.0.22621.2506] -> pcshellcommonproxystub.dll
amd64_microsoft-windows-pcw_31bf3856ad364e35 [10.0.22621.2506] -> pcw.sys
amd64_microsoft-windows-pcwdiagnostic_31bf3856ad364e35 [10.0.22621.2506] -> diagpackage.dll, pcwrun.exe, pcwutl.dll
amd64_microsoft-windows-pdc-mw_31bf3856ad364e35 [10.0.22621.2506] -> kmpdc.sys, pdc.sys
amd64_microsoft-windows-peauth_31bf3856ad364e35 [10.0.22621.2506] -> peauth.sys
amd64_microsoft-windows-peertopeerdrt_31bf3856ad364e35 [10.0.22621.2506] -> drt.dll, drtprov.dll, drttransport.dll
amd64_microsoft-windows-penservice_31bf3856ad364e35 [10.0.22621.2506] -> penservice.dll
amd64_microsoft-windows-peopleband_31bf3856ad364e35 [10.0.22621.2506] -> peopleband.dll
amd64_microsoft-windows-perceptionapi-stub_31bf3856ad364e35 [10.0.22621.2506] -> windows.perception.stub.dll
amd64_microsoft-windows-perceptiondevice-dll_31bf3856ad364e35 [10.0.22621.2506] -> perceptiondevice.dll
amd64_microsoft-windows-photometadatahandler_31bf3856ad364e35 [10.0.22621.2506] -> photometadatahandler.dll
amd64_microsoft-windows-pickerhost_31bf3856ad364e35 [10.0.22621.2506] -> pickerhost.exe
amd64_microsoft-windows-ping-utilities_31bf3856ad364e35 [10.0.22621.2506] -> pathping.exe, ping.exe, tracert.exe
amd64_microsoft-windows-pktmon-setup_31bf3856ad364e35 [10.0.22621.2506] -> pktmon.exe, pktmon.sys, pktmonapi.dll
amd64_microsoft-windows-playtomanager_31bf3856ad364e35 [10.0.22621.2506] -> playtomanager.dll
amd64_microsoft-windows-pnidui_31bf3856ad364e35 [10.0.22621.2506] -> pnidui.dll
amd64_microsoft-windows-pnpdevicemanager_31bf3856ad364e35 [10.0.22621.2506] -> devmgr.dll, dmocx.dll
amd64_microsoft-windows-pnpibs_31bf3856ad364e35 [10.0.22621.2506] -> pnpibs.dll
amd64_microsoft-windows-pnpmigration_31bf3856ad364e35 [10.0.22621.2506] -> pnpmig.dll
amd64_microsoft-windows-pnpsysprep_31bf3856ad364e35 [10.0.22621.2506] -> sppnp.dll
amd64_microsoft-windows-pnpui_31bf3856ad364e35 [10.0.22621.2506] -> pnpui.dll
amd64_microsoft-windows-pnputil_31bf3856ad364e35 [10.0.22621.2506] -> pnputil.exe
amd64_microsoft-windows-powercfg_31bf3856ad364e35 [10.0.22621.2506] -> powercfg.cpl
amd64_microsoft-windows-powershell-exe_31bf3856ad364e35 [10.0.22621.2506] -> powershell.exe
amd64_microsoft-windows-ppi-broker_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.ppi.broker.dll, windows.internal.ppi.broker.proxystub.dll
amd64_microsoft-windows-ppi-config-devicemgmt_31bf3856ad364e35 [10.0.22621.2506] -> devicemgmt.dll, microsoft.azure.activedirectory.graphclient.dll, microsoft.data.edm.dll, microsoft.data.odata.dll, microsoft.data.services.client.dll, microsoft.exchange.webservices.dll, microsoft.identity.client.dll, microsoft.identitymodel.clients.activedirectory.dll, microsoft.identitymodel.clients.activedirectory.windowsforms.dll, microsoft.ppi.config.libraries.aadmgmt.dll, microsoft.ppi.config.libraries.ewsclient.dll, microsoft.ppi.config.libraries.zipfile.dll, system.spatial.dll
amd64_microsoft-windows-ppi-ewssyncservice_31bf3856ad364e35 [10.0.22621.2506] -> ewsclientnative.dll, ewssyncservice.exe
amd64_microsoft-windows-ppi-logcollection_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.ppi.logcollection.exe
amd64_microsoft-windows-ppi-managementservice_31bf3856ad364e35 [10.0.22621.2506] -> ppimansvc.exe
amd64_microsoft-windows-ppi-surfacehubcsp_31bf3856ad364e35 [10.0.22621.2506] -> surfacehubcsp.dll
amd64_microsoft-windows-ppiwelcome.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.ppi.welcome.exe
amd64_microsoft-windows-predictionunit_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.predictionunit.dll
amd64_microsoft-windows-printdialog.core_31bf3856ad364e35 [10.0.22621.2506] -> printdialog.dll, printticketvalidation.dll
amd64_microsoft-windows-printing-appmonitor_31bf3856ad364e35 [10.0.22621.2506] -> appmon.dll
amd64_microsoft-windows-printing-localprinting_31bf3856ad364e35 [10.0.22621.2506] -> apmonportmig.dll, usbportmig.dll
amd64_microsoft-windows-printing-oleprn_31bf3856ad364e35 [10.0.22621.2506] -> oleprn.dll
amd64_microsoft-windows-printing-spooler-core_31bf3856ad364e35 [10.0.22621.2506] -> splwow64.exe, spoolsv.exe
amd64_microsoft-windows-printing-winrt-core_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.printing.dll
amd64_microsoft-windows-printing-workflow_31bf3856ad364e35 [10.0.22621.2506] -> print.printsupport.source.dll, print.workflow.source.dll, printworkflowservice.dll, windows.graphics.printing.workflow.dll, windows.graphics.printing.workflow.native.dll
amd64_microsoft-windows-printing-wsdahost_31bf3856ad364e35 [10.0.22621.2506] -> printwsdahost.dll
amd64_microsoft-windows-printing-xpsprint_31bf3856ad364e35 [10.0.22621.2506] -> xpsprint.dll
amd64_microsoft-windows-printing3d-winrt-core_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.printing.3d.dll
amd64_microsoft-windows-profapi-onecore_31bf3856ad364e35 [10.0.22621.2506] -> profapi.dll
amd64_microsoft-windows-profsvc-mof_31bf3856ad364e35 [10.0.22621.2506] -> profprov.dll
amd64_microsoft-windows-profsvc_31bf3856ad364e35 [10.0.22621.2506] -> profsvc.dll
amd64_microsoft-windows-profsvcext_31bf3856ad364e35 [10.0.22621.2506] -> profsvcext.dll
amd64_microsoft-windows-projfs-api_31bf3856ad364e35 [10.0.22621.2506] -> projectedfslib.dll
amd64_microsoft-windows-projfs-driver_31bf3856ad364e35 [10.0.22621.2506] -> prjflt.sys
amd64_microsoft-windows-propsys_31bf3856ad364e35 [7.0.22621.2506] -> propsys.dll
amd64_microsoft-windows-proquota_31bf3856ad364e35 [10.0.22621.2506] -> proquota.exe
amd64_microsoft-windows-provisioning-core_31bf3856ad364e35 [10.0.22621.2506] -> barcodeprovisioningplugin.dll, knobscore.dll, knobscsp.dll, nfcprovisioningplugin.dll, provdatastore.dll, provengine.dll, provhandlers.dll, provisioningcsp.dll, provops.dll, provplugineng.dll, provtool.exe, removablemediaprovisioningplugin.dll, windows.management.provisioning.proxystub.dll
amd64_microsoft-windows-provisioning-platform_31bf3856ad364e35 [10.0.22621.2506] -> provcmdlets.dll, provcommon.dll, provisioningcommandscsp.dll, provlaunch.exe, provmigrate.dll, provplatformdesktop.dll, wiminterop.dll
amd64_microsoft-windows-provisioningcore_31bf3856ad364e35 [10.0.22621.2506] -> provcore.dll
amd64_microsoft-windows-provisioningxml_31bf3856ad364e35 [10.0.22621.2506] -> wpx.dll
amd64_microsoft-windows-proximity-service_31bf3856ad364e35 [10.0.22621.2506] -> proximityservice.dll
amd64_microsoft-windows-psmcoreserver_31bf3856ad364e35 [10.0.22621.2506] -> psmsrv.dll
amd64_microsoft-windows-qwave_31bf3856ad364e35 [10.0.22621.2506] -> qwave.dll, qwavedrv.sys
amd64_microsoft-windows-r..-profile-hardwareid_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.profile.hardwareid.dll
amd64_microsoft-windows-r..-service.deployment_31bf3856ad364e35 [10.0.22621.2506] -> rdxservice.dll
amd64_microsoft-windows-r..ase-rassstp-coresys_31bf3856ad364e35 [10.0.22621.2506] -> rassstp.sys
amd64_microsoft-windows-r..ckgroundmediaplayer_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.backgroundmediaplayback.dll, windows.media.backgroundplayback.exe, windows.media.playback.backgroundmediaplayer.dll, windows.media.playback.mediaplayer.dll, windows.media.playback.proxystub.dll
amd64_microsoft-windows-r..ndows-media-renewal_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.renewal.dll
amd64_microsoft-windows-r..s-regkeys-component_31bf3856ad364e35 [10.0.22621.2506] -> rdpcorets.dll, rdpcredentialprovider.dll, rdpudd.dll, rdpvideominiport.sys
amd64_microsoft-windows-r..sistance-dcomserver_31bf3856ad364e35 [10.0.22621.2506] -> raserver.exe
amd64_microsoft-windows-r..systemmanufacturers_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.profile.systemmanufacturers.dll
amd64_microsoft-windows-r..topservices-rdpbase_31bf3856ad364e35 [10.0.22621.2506] -> rdpbase.dll
amd64_microsoft-windows-rasbase-agilevpn_31bf3856ad364e35 [10.0.22621.2506] -> agilevpn.sys, vpnike.dll
amd64_microsoft-windows-rasbase-core_31bf3856ad364e35 [10.0.22621.2506] -> ndistapi.sys, ndproxy.sys, wanarp.sys
amd64_microsoft-windows-rasbase-ndiswan_31bf3856ad364e35 [10.0.22621.2506] -> ndiswan.sys
amd64_microsoft-windows-rasbase-rascustom_31bf3856ad364e35 [10.0.22621.2506] -> rascustom.dll
amd64_microsoft-windows-rasbase-rasl2tp_31bf3856ad364e35 [10.0.22621.2506] -> rasl2tp.sys
amd64_microsoft-windows-rasbase-raspppoe_31bf3856ad364e35 [10.0.22621.2506] -> raspppoe.sys
amd64_microsoft-windows-rasbase-raspptp_31bf3856ad364e35 [10.0.22621.2506] -> raspptp.sys
amd64_microsoft-windows-rasbase-rassstp_31bf3856ad364e35 [10.0.22621.2506] -> sstpsvc.dll
amd64_microsoft-windows-rasmanservice_31bf3856ad364e35 [10.0.22621.2506] -> rasmans.dll
amd64_microsoft-windows-rasmprsnap_31bf3856ad364e35 [10.0.22621.2506] -> mprsnap.dll
amd64_microsoft-windows-rasppp-noneap_31bf3856ad364e35 [10.0.22621.2506] -> rasppp.dll
amd64_microsoft-windows-rasrtutils_31bf3856ad364e35 [10.0.22621.2506] -> rtutils.dll
amd64_microsoft-windows-rasserver_31bf3856ad364e35 [10.0.22621.2506] -> iprtprio.dll, iprtrmgr.dll, mprdim.dll, rasmigplugin.dll, rtm.dll
amd64_microsoft-windows-rastls_31bf3856ad364e35 [10.0.22621.2506] -> rastlsext.dll
amd64_microsoft-windows-rdbss_31bf3856ad364e35 [10.0.22621.2506] -> rdbss.sys
amd64_microsoft-windows-readyboostdriver_31bf3856ad364e35 [10.0.22621.2506] -> rdyboost.sys
amd64_microsoft-windows-recovery-cleanpc_31bf3856ad364e35 [10.0.22621.2506] -> cleanpccsp.dll
amd64_microsoft-windows-refs-v1_31bf3856ad364e35 [10.0.22621.2506] -> refsv1.sys
amd64_microsoft-windows-refs_31bf3856ad364e35 [10.0.22621.2506] -> refs.sys
amd64_microsoft-windows-refsutil_31bf3856ad364e35 [10.0.22621.2506] -> refsutil.exe
amd64_microsoft-windows-reliability-postboot_31bf3856ad364e35 [10.0.22621.2506] -> relpost.exe
amd64_microsoft-windows-remoteassistance-diag_31bf3856ad364e35 [10.0.22621.2506] -> msrahc.dll
amd64_microsoft-windows-remoteassistance-exe_31bf3856ad364e35 [10.0.22621.2506] -> msra.exe, racpldlg.dll, sdchange.exe
amd64_microsoft-windows-remoteregistry-service_31bf3856ad364e35 [10.0.22621.2715] * -> regsvc.dll
amd64_microsoft-windows-resampledmo_31bf3856ad364e35 [10.0.22621.2506] -> resampledmo.dll
amd64_microsoft-windows-reset-edgeresetplugin_31bf3856ad364e35 [10.0.22621.2506] -> edgeresetplugin.dll
amd64_microsoft-windows-resourcemanager-client_31bf3856ad364e35 [10.0.22621.2506] -> rmclient.dll
amd64_microsoft-windows-resourcemanager-server_31bf3856ad364e35 [10.0.22621.2506] -> psmserviceexthost.dll
amd64_microsoft-windows-retaildemo-retailinfo_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.profile.retailinfo.dll
amd64_microsoft-windows-riched32_31bf3856ad364e35 [10.0.22621.2506] -> riched20.dll, riched32.dll
amd64_microsoft-windows-rjvmdmconfig_31bf3856ad364e35 [10.0.22621.2506] -> rjvmdmconfig.dll
amd64_microsoft-windows-rmapi_31bf3856ad364e35 [10.0.22621.2506] -> rmapi.dll
amd64_microsoft-windows-rmcast_31bf3856ad364e35 [10.0.22621.2715] * -> rmcast.sys, wshrm.dll
amd64_microsoft-windows-robocopy_31bf3856ad364e35 [10.0.22621.2506] -> robocopy.exe
amd64_microsoft-windows-rpc-endpointmapper_31bf3856ad364e35 [10.0.22621.2506] -> rpcepmap.dll
amd64_microsoft-windows-rpc-http_31bf3856ad364e35 [10.0.22621.2506] -> rpchttp.dll
amd64_microsoft-windows-rpc-kernel_31bf3856ad364e35 [10.0.22621.2506] -> msrpc.sys
amd64_microsoft-windows-rpc-local_31bf3856ad364e35 [10.0.22621.2506] -> rpcrt4.dll
amd64_microsoft-windows-rpc-remote-extension_31bf3856ad364e35 [10.0.22621.2506] -> rpcrtremote.dll
amd64_microsoft-windows-runonce_31bf3856ad364e35 [10.0.22621.2506] -> runonce.exe
amd64_microsoft-windows-runtime-windows-media_31bf3856ad364e35 [10.0.22621.2715] * -> windows.media.dll
amd64_microsoft-windows-s..-bluelightreduction_31bf3856ad364e35 [10.0.22621.2506] -> windows.shell.bluelightreduction.dll
amd64_microsoft-windows-s..-credentialprovider_31bf3856ad364e35 [10.0.22621.2506] -> biocredprov.dll
amd64_microsoft-windows-s..-desktoptaskfactory_31bf3856ad364e35 [10.0.22621.2506] -> rdxtaskfactory.dll
amd64_microsoft-windows-s..-installers-onecore_31bf3856ad364e35 [10.0.22621.2567] -> appxprovisionpackage.dll, appxreg.dll, cmifw.dll, edgeai.dll, eventsinstaller.dll, firewallofflineapi.dll, grouptrusteeai.dll, hotpatchai.dll, httpai.dll, implatsetup.dll, luainstall.dll, netfxconfig.dll, netsetupai.dll, netsetupapi.dll, netsetupengine.dll, perfcounterinstaller.dll, timezoneai.dll, winsockai.dll, wmicmiplugin.dll, ws2_helper.dll
amd64_microsoft-windows-s..-servicehostbuilder_31bf3856ad364e35 [10.0.22621.2506] -> windows.shell.servicehostbuilder.dll
amd64_microsoft-windows-s..-spp-plugin-windows_31bf3856ad364e35 [10.0.22621.2506] -> sppwinob.dll
amd64_microsoft-windows-s..-universal-internal_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.devices.sensors.dll
amd64_microsoft-windows-s..-userexperienceinfo_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_userexperience.dll
amd64_microsoft-windows-s..agespaces-spaceutil_31bf3856ad364e35 [10.0.22621.2506] -> spaceutil.exe
amd64_microsoft-windows-s..andlers-analogshell_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_analogshell.dll
amd64_microsoft-windows-s..andlers-useraccount_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_useraccount.dll
amd64_microsoft-windows-s..ardsubsystem-extras_31bf3856ad364e35 [10.0.22621.2506] -> certprop.dll, scarddlg.dll, scdeviceenum.dll, scfilter.sys
amd64_microsoft-windows-s..artcard-tpm-manager_31bf3856ad364e35 [10.0.22621.2506] -> immersivetpmvscmgrsvr.exe, rmttpmvscmgrsvr.exe, tpmvscmgr.exe, tpmvscmgrsvr.exe
amd64_microsoft-windows-s..aryauthfactor-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.security.authentication.identity.provider.dll
amd64_microsoft-windows-s..ative-serverbox-isv_31bf3856ad364e35 [10.0.22621.2506] -> rmactivate_ssp_isv.exe, secproc_ssp_isv.dll
amd64_microsoft-windows-s..authfactor-credprov_31bf3856ad364e35 [10.0.22621.2506] -> devicengccredprov.dll
amd64_microsoft-windows-s..biometrics-trustlet_31bf3856ad364e35 [10.0.22621.2506] -> bioiso.exe
amd64_microsoft-windows-s..brokeringfilesystem_31bf3856ad364e35 [10.0.22621.2506] -> bfs.sys
amd64_microsoft-windows-s..card-gids-simulator_31bf3856ad364e35 [10.0.22621.2506] -> smartcardsimulator.dll
amd64_microsoft-windows-s..cecontroller-minwin_31bf3856ad364e35 [10.0.22621.2506] -> services.exe
amd64_microsoft-windows-s..ces-backgroundagent_31bf3856ad364e35 [10.0.22621.2506] -> spaceagent.exe
amd64_microsoft-windows-s..ces-targetedcontent_31bf3856ad364e35 [10.0.22621.2506] -> windows.services.targetedcontent.dll
amd64_microsoft-windows-s..cingstack-onecoreds_31bf3856ad364e35 [10.0.22621.2567] -> offlinelsa.dll, offlinesam.dll
amd64_microsoft-windows-s..ck-mof-onecoreadmin_31bf3856ad364e35 [10.0.22621.2567] -> esscli.dll, fastprox.dll, mofd.dll, mofinstall.dll, repdrvfs.dll, wbemcomn.dll, wbemcore.dll, wbemprox.dll, wmiutils.dll
amd64_microsoft-windows-s..configurationengine_31bf3856ad364e35 [10.0.22621.2506] -> scesrv.dll
amd64_microsoft-windows-s..csengine-nativehost_31bf3856ad364e35 [10.0.22621.2506] -> sdiagnhost.exe
amd64_microsoft-windows-s..daryauthfactor-task_31bf3856ad364e35 [10.0.22621.2506] -> devicecredentialdeployment.exe
amd64_microsoft-windows-s..ddriverprovider-dll_31bf3856ad364e35 [10.0.22621.2506] -> signdrv.dll
amd64_microsoft-windows-s..defaultassociations_31bf3856ad364e35 [10.0.22621.2506] -> oemdefaultassociations.dll
amd64_microsoft-windows-s..deosettingshandlers_31bf3856ad364e35 [10.0.22621.2506] -> videohandlers.dll
amd64_microsoft-windows-s..diosettingshandlers_31bf3856ad364e35 [10.0.22621.2506] -> audiohandlers.dll
amd64_microsoft-windows-s..dlers-accessibility_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_accessibility.dll
amd64_microsoft-windows-s..dlers-extensibility_31bf3856ad364e35 [10.0.22621.2506] -> settingsextensibilityhandlers.dll
amd64_microsoft-windows-s..dlers-humanpresence_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_humanpresence.dll
amd64_microsoft-windows-s..dlers-notifications_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_notifications.dll
amd64_microsoft-windows-s..dlers-powerandsleep_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_onecore_powerandsleep.dll
amd64_microsoft-windows-s..e-client-ui-wsreset_31bf3856ad364e35 [10.0.22621.2506] -> wsreset.exe
amd64_microsoft-windows-s..e-windowsupdateauth_31bf3856ad364e35 [10.0.22621.2506] -> storewuauth.dll, storewuauthcore.dll
amd64_microsoft-windows-s..edpc-accountmanager_31bf3856ad364e35 [10.0.22621.2506] -> windows.sharedpc.accountmanager.dll
amd64_microsoft-windows-s..elligentpwdlesstask_31bf3856ad364e35 [10.0.22621.2506] -> intelligentpwdlesstask.dll
amd64_microsoft-windows-s..em-events-container_31bf3856ad364e35 [10.0.22621.2506] -> microsoft-windows-system-events.dll
amd64_microsoft-windows-s..ementwmi-powershell_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.storage.core.dll, microsoft.windows.storage.storagebuscache.dll
amd64_microsoft-windows-s..emsettingsthreshold_31bf3856ad364e35 [10.0.22621.2715] * -> systemsettings.dll, systemsettingsviewmodel.desktop.dll, telemetry.common.dll
amd64_microsoft-windows-s..enanceservice-rdbui_31bf3856ad364e35 [10.0.22621.2506] -> rdbui.dll
amd64_microsoft-windows-s..engine-nativeengine_31bf3856ad364e35 [10.0.22621.2506] -> sdiageng.dll
amd64_microsoft-windows-s..entication-usermode_31bf3856ad364e35 [10.0.22621.2506] -> authz.dll
amd64_microsoft-windows-s..erdatamodel-desktop_31bf3856ad364e35 [10.0.22621.2506] -> desktopswitcherdatamodel.dll
amd64_microsoft-windows-s..ettingshandlers-gpu_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_gpu.dll
amd64_microsoft-windows-s..ettingshandlers-ime_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_ime.dll
amd64_microsoft-windows-s..ettingshandlers-pen_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_pen.dll
amd64_microsoft-windows-s..ettingshandlers-usb_31bf3856ad364e35 [10.0.22621.2506] -> usbsettingshandlers.dll
amd64_microsoft-windows-s..formers-shell-extra_31bf3856ad364e35 [10.0.22621.2567] -> shtransform.dll
amd64_microsoft-windows-s..gshandlers-language_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_language.dll
amd64_microsoft-windows-s..gshandlers-lighting_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_lighting.dll
amd64_microsoft-windows-s..gstack-boot-onecore_31bf3856ad364e35 [10.0.22621.2567] -> bfsvc.dll, fveupdateai.dll, securebootai.dll
amd64_microsoft-windows-s..handlers-userintent_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_userintent.dll
amd64_microsoft-windows-s..handlers-workaccess_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_workaccess.dll
amd64_microsoft-windows-s..holographicruntimes_31bf3856ad364e35 [10.0.22621.2506] -> holographicruntimes.dll
amd64_microsoft-windows-s..hreshold-adminflows_31bf3856ad364e35 [10.0.22621.2506] -> systemsettingsadminflows.exe, systemsettingsthresholdadminflowui.dll
amd64_microsoft-windows-s..icate-policy-engine_31bf3856ad364e35 [10.0.22621.2506] -> certpoleng.dll
amd64_microsoft-windows-s..icsclient-scheduled_31bf3856ad364e35 [10.0.22621.2506] -> sdiagschd.dll
amd64_microsoft-windows-s..ings-handlersplugin_31bf3856ad364e35 [10.0.22621.2506] -> systemsettings.handlers.dll
amd64_microsoft-windows-s..ingshandlers-backup_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_backup.dll
amd64_microsoft-windows-s..ingshandlers-camera_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_camera.dll
amd64_microsoft-windows-s..ingshandlers-gaming_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_gaming.dll
amd64_microsoft-windows-s..ingshandlers-region_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_region.dll
amd64_microsoft-windows-s..ity-netlogon-netapi_31bf3856ad364e35 [10.0.22621.2506] -> logoncli.dll
amd64_microsoft-windows-s..k-transformers-core_31bf3856ad364e35 [10.0.22621.2567] -> primitivetransformers.dll
amd64_microsoft-windows-s..l-classextension-v2_31bf3856ad364e35 [10.0.22621.2506] -> sercx2.sys
amd64_microsoft-windows-s..l-family-syncengine_31bf3856ad364e35 [10.0.22621.2506] -> family.syncengine.dll
amd64_microsoft-windows-s..l-winuicohabitation_31bf3856ad364e35 [10.0.22621.2506] -> winuicohabitation.dll
amd64_microsoft-windows-s..lcommon.startdocked_31bf3856ad364e35 [10.0.22621.2715] * -> startdocked.dll
amd64_microsoft-windows-s..lerevocationmanager_31bf3856ad364e35 [10.0.22621.2506] -> efswrt.dll
amd64_microsoft-windows-s..lers-assignedaccess_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_assignedaccess.dll
amd64_microsoft-windows-s..lers-authentication_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_authentication.dll
amd64_microsoft-windows-s..lers-backgroundapps_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_backgroundapps.dll
amd64_microsoft-windows-s..lers-onedrivebackup_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_onedrivebackup.dll
amd64_microsoft-windows-s..lessplat-aggregator_31bf3856ad364e35 [10.0.22621.2506] -> pwdlessaggregator.dll
amd64_microsoft-windows-s..licationframe-frame_31bf3856ad364e35 [10.0.22621.2506] -> applicationframe.dll
amd64_microsoft-windows-s..llers-onecore-extra_31bf3856ad364e35 [10.0.22621.2567] -> bcdeditai.dll, configureieoptionalcomponentsai.dll, featuresettingsoverride.dll, iefileinstallai.dll, msdtcadvancedinstaller.dll, netfxconfig.dll, peerdistai.dll, printadvancedinstaller.dll, servicemodelregai.dll, setieinstalleddateai.dll, sppinst.dll
amd64_microsoft-windows-s..lographicextensions_31bf3856ad364e35 [10.0.22621.2506] -> holographicextensions.dll
amd64_microsoft-windows-s..manager-service-api_31bf3856ad364e35 [10.0.22621.2506] -> licensemanagerapi.dll, tempsignedlicenseexchangetask.dll
amd64_microsoft-windows-s..mmoncommonproxystub_31bf3856ad364e35 [10.0.22621.2506] -> shellcommoncommonproxystub.dll
amd64_microsoft-windows-s..msettings-datamodel_31bf3856ad364e35 [10.0.22621.2715] * -> systemsettings.datamodel.dll, systemsettingsbroker.exe
amd64_microsoft-windows-s..native-whitebox-isv_31bf3856ad364e35 [10.0.22621.2506] -> rmactivate_isv.exe, secproc_isv.dll
amd64_microsoft-windows-s..ncehost.shellcommon_31bf3856ad364e35 [10.0.22621.2715] * -> startui.dll
amd64_microsoft-windows-s..ndlers-batteryusage_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_batteryusage.dll
amd64_microsoft-windows-s..ndlers-storagesense_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_storagesense.dll
amd64_microsoft-windows-s..necore-batterysaver_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_onecore_batterysaver.dll
amd64_microsoft-windows-s..ngc-ctnrgidshandler_31bf3856ad364e35 [10.0.22621.2506] -> ngcctnrgidshandler.dll
amd64_microsoft-windows-s..ngerprintcredential_31bf3856ad364e35 [10.0.22621.2506] -> fingerprintcredential.dll
amd64_microsoft-windows-s..ngshandlers-cortana_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_cortana.dll
amd64_microsoft-windows-s..ngshandlers-devices_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_devices.dll
amd64_microsoft-windows-s..ngshandlers-display_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_display.dll
amd64_microsoft-windows-s..ngshandlers-startup_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_startup.dll
amd64_microsoft-windows-s..ngshandlers-storage_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_storage.dll
amd64_microsoft-windows-s..ngstack-onecorebase_31bf3856ad364e35 [10.0.22621.2567] -> grouptrusteeai.dll
amd64_microsoft-windows-s..nload-scheduledtask_31bf3856ad364e35 [10.0.22621.2506] -> themes.ssfdownload.scheduledtask.dll
amd64_microsoft-windows-s..nputpersonalization_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_inputpersonalization.dll
amd64_microsoft-windows-s..nsemanager-shellext_31bf3856ad364e35 [10.0.22621.2506] -> licensemanagershellext.exe
amd64_microsoft-windows-s..nt-enrollmenthelper_31bf3856ad364e35 [10.0.22621.2506] -> pinenrollmentbroker.exe, pinenrollmenthelper.dll
amd64_microsoft-windows-s..okerplugin.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> aad.core.dll, microsoft.aad.brokerplugin.exe
amd64_microsoft-windows-s..ololens-environment_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_hololens_environment.dll
amd64_microsoft-windows-s..ompat-media-onecore_31bf3856ad364e35 [10.0.22621.2715] * -> compatctrl.dll, setupcompat.dll
amd64_microsoft-windows-s..on-brokerfiledialog_31bf3856ad364e35 [10.0.22621.2506] -> brokerfiledialog.dll
amd64_microsoft-windows-s..on-energyestimation_31bf3856ad364e35 [10.0.22621.2506] -> eeprov.dll
amd64_microsoft-windows-s..on-filedialogbroker_31bf3856ad364e35 [10.0.22621.2506] -> filedialogbroker.exe
amd64_microsoft-windows-s..on-onlineid-runtime_31bf3856ad364e35 [10.0.22621.2506] -> windows.security.authentication.onlineid.dll
amd64_microsoft-windows-s..on-wizard-framework_31bf3856ad364e35 [10.0.22621.2506] -> spwizeng.dll, spwizimg.dll, spwizres.dll, uxlib.dll, uxlibres.dll
amd64_microsoft-windows-s..onssettingshandlers_31bf3856ad364e35 [10.0.22621.2506] -> developeroptionssettingshandlers.dll
amd64_microsoft-windows-s..or-native-serverbox_31bf3856ad364e35 [10.0.22621.2506] -> rmactivate_ssp.exe, secproc_ssp.dll
amd64_microsoft-windows-s..osoftaccountcloudap_31bf3856ad364e35 [10.0.22621.2506] -> microsoftaccountcloudap.dll
amd64_microsoft-windows-s..ost-ppi.shellcommon_31bf3856ad364e35 [10.0.22621.2715] * -> clockflyoutexperience.dll, devicesflowui.dll, mtcuvc.dll, sharepickerui.dll, windows.ui.actioncenter.dll, windows.ui.quickactions.dll
amd64_microsoft-windows-s..platform-media-base_31bf3856ad364e35 [10.0.22621.2506] -> diager.dll, diagtrack.dll, diagtrackrunner.exe, hwcompat.dll, reagent.dll, setupplatform.dll, setupplatform.exe, unbcl.dll, wdsclientapi.dll, wdscore.dll, wdscsl.dll, wdsimage.dll, wdstptc.dll, wdsutil.dll
amd64_microsoft-windows-s..plicationframe-host_31bf3856ad364e35 [10.0.22621.2506] -> applicationframehost.exe
amd64_microsoft-windows-s..ransformers-onecore_31bf3856ad364e35 [10.0.22621.2567] -> aritransformer.dll, wpndatatransformer.dll
amd64_microsoft-windows-s..rationmanagement-ui_31bf3856ad364e35 [10.0.22621.2506] -> wsecedit.dll
amd64_microsoft-windows-s..rd-tpm-vcard-module_31bf3856ad364e35 [10.0.22621.2506] -> tpmvsc.dll
amd64_microsoft-windows-s..redexperiences-rome_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_sharedexperiences_rome.dll
amd64_microsoft-windows-s..restartup-basic-cpl_31bf3856ad364e35 [10.0.22621.2506] -> bitlockerwizardelev.exe, fvecpl.dll, fvewiz.dll
amd64_microsoft-windows-s..rics-storageadapter_31bf3856ad364e35 [10.0.22621.2506] -> winbiostorageadapter.dll
amd64_microsoft-windows-s..riencehost.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> batteryflyoutexperience.dll, imestatusnotification.dll, inputdial.dll, insights.dll, penworkspace.dll, quickconnectui.dll, shellexperiencehost.exe, virtualtouchpadui.dll, windows.ui.softlanding.dll
amd64_microsoft-windows-s..rity-spp-validation_31bf3856ad364e35 [10.0.22621.2506] -> genvalobj.exe
amd64_microsoft-windows-s..roubleshoothandlers_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_troubleshoot.dll
amd64_microsoft-windows-s..rovisioninghandlers_31bf3856ad364e35 [10.0.22621.2506] -> provisioninghandlers.dll
amd64_microsoft-windows-s..rs-keyboard-desktop_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_keyboard.dll
amd64_microsoft-windows-s..ryauthfactor-client_31bf3856ad364e35 [10.0.22621.2506] -> devicecredential.dll
amd64_microsoft-windows-s..s-appexecutionalias_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_appexecutionalias.dll
amd64_microsoft-windows-s..s-vsmstorageadapter_31bf3856ad364e35 [10.0.22621.2506] -> winbiovsmstorageadapter.dll
amd64_microsoft-windows-s..seraccountshandlers_31bf3856ad364e35 [10.0.22621.2506] -> systemsettings.useraccountshandlers.dll
amd64_microsoft-windows-s..settingshandlers-nt_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_nt.dll
amd64_microsoft-windows-s..shandlers-clipboard_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_clipboard.dll
amd64_microsoft-windows-s..shandlers-pcdisplay_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_pcdisplay.dll
amd64_microsoft-windows-s..shtoinstall-service_31bf3856ad364e35 [10.0.22621.2506] -> pushtoinstall.dll
amd64_microsoft-windows-s..sor-native-whitebox_31bf3856ad364e35 [10.0.22621.2715] * -> rmactivate.exe, secproc.dll
amd64_microsoft-windows-s..spaces-controlpanel_31bf3856ad364e35 [10.0.22621.2506] -> spacecontrol.dll
amd64_microsoft-windows-s..spaces-spacemanager_31bf3856ad364e35 [10.0.22621.2506] -> spaceman.exe
amd64_microsoft-windows-s..spellcheck.binaries_31bf3856ad364e35 [10.0.22621.2506] -> msspellcheckingfacility.dll
amd64_microsoft-windows-s..stack-inetsrv-extra_31bf3856ad364e35 [10.0.22621.2567] -> mqcmiplugin.dll
amd64_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35 [10.0.22621.2567] -> appserverai.dll, rdwebai.dll, tssdisai.dll, vmhostai.dll
amd64_microsoft-windows-s..stedsignal-credprov_31bf3856ad364e35 [10.0.22621.2506] -> trustedsignalcredprov.dll
amd64_microsoft-windows-s..tartup-filterdriver_31bf3856ad364e35 [10.0.22621.2506] -> dumpfve.sys, fvevol.sys
amd64_microsoft-windows-s..te-ppiupdatemanager_31bf3856ad364e35 [10.0.22621.2506] -> ppiupdatemanager.exe
amd64_microsoft-windows-s..tenanceservice-core_31bf3856ad364e35 [10.0.22621.2506] -> sysmain.dll
amd64_microsoft-windows-s..tentdeliverymanager_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_contentdeliverymanager.dll
amd64_microsoft-windows-s..tform-media-onecore_31bf3856ad364e35 [10.0.22621.2506] -> bcd.dll, bootsvc.dll, dismapi.dll, dismcore.dll, dismcoreps.dll, dismprov.dll, folderprovider.dll, hwreqchk.dll, imagingprovider.dll, logprovider.dll, nlsbres.dll, servicingcommon.dll, unattend.dll, utcapi.dll, vhdprovider.dll, wdscommonlib.dll, wimgapi.dll, wimprovider.dll, wpx.dll
amd64_microsoft-windows-s..ting-jscript9legacy_31bf3856ad364e35 [11.0.22621.2715] * -> jscript9legacy.dll
amd64_microsoft-windows-s..tingshandlers-about_31bf3856ad364e35 [10.0.22621.2506] -> aboutsettingshandlers.dll
amd64_microsoft-windows-s..tingshandlers-phone_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_managephone.dll
amd64_microsoft-windows-s..ttingsextensibility_31bf3856ad364e35 [10.0.22621.2506] -> systemsettings.settingsextensibility.dll
amd64_microsoft-windows-s..ttingshandlers-maps_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_maps.dll
amd64_microsoft-windows-s..ttingshandlers-siuf_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_siuf.dll
amd64_microsoft-windows-s..ttingshandlers-user_31bf3856ad364e35 [10.0.22621.2506] -> settingshandlers_user.dll
amd64_microsoft-windows-s..turalauthentication_31bf3856ad364e35 [10.0.22621.2506] -> naturalauth.dll, naturalauthclient.dll
amd64_microsoft-windows-s..tworkmobilehandlers_31bf3856ad364e35 [10.0.22621.2506] -> networkmobilesettings.dll
amd64_microsoft-windows-s..ty-aadcloudapplugin_31bf3856ad364e35 [10.0.22621.2506] -> aadcloudap.dll
amd64_microsoft-windows-s..ty-cng-keyisolation_31bf3856ad364e35 [10.0.22621.2506] -> keyiso.dll
amd64_microsoft-windows-s..ty-integrity-policy_31bf3856ad364e35 [10.0.22621.2506] -> windows.security.integrity.dll
amd64_microsoft-windows-s..ty-kerbclientshared_31bf3856ad364e35 [10.0.22621.2506] -> kerbclientshared.dll
amd64_microsoft-windows-s..ty-ngc-isocontainer_31bf3856ad364e35 [10.0.22621.2506] -> ngcisoctnr.dll
amd64_microsoft-windows-s..urationengineclient_31bf3856ad364e35 [10.0.22621.2506] -> scecli.dll
amd64_microsoft-windows-s..voicecommon-onecore_31bf3856ad364e35 [10.0.22621.2506] -> msttsengine_onecore.dll, msttsloc_onecore.dll
amd64_microsoft-windows-s..workdesktophandlers_31bf3856ad364e35 [10.0.22621.2506] -> networkdesktopsettings.dll
amd64_microsoft-windows-s..y-biometrics-client_31bf3856ad364e35 [10.0.22621.2506] -> winbio.dll
amd64_microsoft-windows-s..y-spp-plugin-common_31bf3856ad364e35 [10.0.22621.2715] * -> sppobjs.dll
amd64_microsoft-windows-s..y-spp-virtualdevice_31bf3856ad364e35 [10.0.22621.2715] * -> activationvdev.dll
amd64_microsoft-windows-safedocs-main_31bf3856ad364e35 [10.0.22621.2506] -> sdclt.exe, sdengin2.dll, sdrsvc.dll, sdshext.dll
amd64_microsoft-windows-scripting-chakra_31bf3856ad364e35 [11.0.22621.2506] -> chakra.dll, chakradiag.dll, chakrathunk.dll
amd64_microsoft-windows-scripting-jscript9_31bf3856ad364e35 [11.0.22621.2715] * -> jscript9.dll, jscript9diag.dll
amd64_microsoft-windows-scripting-jscript_31bf3856ad364e35 [11.0.22621.2506] -> jscript.dll
amd64_microsoft-windows-scripting-vbscript_31bf3856ad364e35 [11.0.22621.2506] -> vbscript.dll
amd64_microsoft-windows-scripting_31bf3856ad364e35 [10.0.22621.2506] -> cscript.exe, dispex.dll, scrobj.dll, scrrun.dll, wscript.exe, wshcon.dll, wshom.ocx
amd64_microsoft-windows-sdport_31bf3856ad364e35 [10.0.22621.2506] -> sdport.sys
amd64_microsoft-windows-search-profilenotify_31bf3856ad364e35 [7.0.22621.2506] -> wsepno.dll
amd64_microsoft-windows-searchfolder-library_31bf3856ad364e35 [10.0.22621.2506] -> searchfolder.dll
amd64_microsoft-windows-sechost_31bf3856ad364e35 [10.0.22621.2506] -> sechost.dll
amd64_microsoft-windows-secondarylogonservice_31bf3856ad364e35 [10.0.22621.2506] -> seclogon.dll
amd64_microsoft-windows-securestartup-core_31bf3856ad364e35 [10.0.22621.2506] -> fveapi.dll, fveapibase.dll
amd64_microsoft-windows-securestartup-cpl_31bf3856ad364e35 [10.0.22621.2506] -> bitlockerwizard.exe, bitlockerwizardelev.exe, fvecpl.dll, fvewiz.dll
amd64_microsoft-windows-securestartup-service_31bf3856ad364e35 [10.0.22621.2506] -> bdesvc.dll, bdeuisrv.exe
amd64_microsoft-windows-security-aadauthhelper_31bf3856ad364e35 [10.0.22621.2506] -> aadauthhelper.dll
amd64_microsoft-windows-security-aadtb_31bf3856ad364e35 [10.0.22621.2506] -> aadtb.dll
amd64_microsoft-windows-security-apphvsi-adm_31bf3856ad364e35 [10.0.22621.2506] -> hvsigpext.dll
amd64_microsoft-windows-security-cfl-api_31bf3856ad364e35 [10.0.22621.2506] -> cflapi.dll
amd64_microsoft-windows-security-cloudap_31bf3856ad364e35 [10.0.22621.2506] -> cloudap.dll
amd64_microsoft-windows-security-credssp_31bf3856ad364e35 [10.0.22621.2715] * -> credssp.dll, tspkg.dll
amd64_microsoft-windows-security-cx-credprov_31bf3856ad364e35 [10.0.22621.2506] -> cxcredprov.dll
amd64_microsoft-windows-security-digest_31bf3856ad364e35 [10.0.22621.2715] * -> wdigest.dll
amd64_microsoft-windows-security-fido-credprov_31bf3856ad364e35 [10.0.22621.2506] -> fidocredprov.dll
amd64_microsoft-windows-security-identitystore_31bf3856ad364e35 [10.0.22621.2506] -> idstore.dll
amd64_microsoft-windows-security-kerberos_31bf3856ad364e35 [10.0.22621.2715] * -> kerberos.dll
amd64_microsoft-windows-security-lsatrustlet_31bf3856ad364e35 [10.0.22621.2506] -> iumcrypt.dll, lsaiso.exe
amd64_microsoft-windows-security-negoexts_31bf3856ad364e35 [10.0.22621.2715] * -> negoexts.dll
amd64_microsoft-windows-security-netlogon_31bf3856ad364e35 [10.0.22621.2506] -> netlogon.dll
amd64_microsoft-windows-security-ngc-container_31bf3856ad364e35 [10.0.22621.2506] -> ngcctnr.dll
amd64_microsoft-windows-security-ngc-credprov_31bf3856ad364e35 [10.0.22621.2506] -> ngccredprov.dll
amd64_microsoft-windows-security-ngc-cryptngc_31bf3856ad364e35 [10.0.22621.2506] -> cryptngc.dll
amd64_microsoft-windows-security-ngc-csp_31bf3856ad364e35 [10.0.22621.2506] -> ngcprocsp.dll
amd64_microsoft-windows-security-ngc-ctnrsvc_31bf3856ad364e35 [10.0.22621.2506] -> ngcctnrsvc.dll
amd64_microsoft-windows-security-ngc-hmkd_31bf3856ad364e35 [10.0.22621.2715] * -> hmkd.dll
amd64_microsoft-windows-security-ngc-keyenum_31bf3856ad364e35 [10.0.22621.2506] -> ngckeyenum.dll
amd64_microsoft-windows-security-ngc-ksp_31bf3856ad364e35 [10.0.22621.2506] -> ngcksp.dll
amd64_microsoft-windows-security-ngc-kspsvc_31bf3856ad364e35 [10.0.22621.2506] -> ngcsvc.dll
amd64_microsoft-windows-security-ngc-local_31bf3856ad364e35 [10.0.22621.2506] -> ngclocal.dll
amd64_microsoft-windows-security-ngc-popkeysrv_31bf3856ad364e35 [10.0.22621.2506] -> ngcpopkeysrv.dll
amd64_microsoft-windows-security-ngc-recovery_31bf3856ad364e35 [10.0.22621.2506] -> ngcrecovery.dll
amd64_microsoft-windows-security-ngc-tasks_31bf3856ad364e35 [10.0.22621.2506] -> ngctasks.dll
amd64_microsoft-windows-security-ngc-trustlet_31bf3856ad364e35 [10.0.22621.2506] -> ngciso.exe
amd64_microsoft-windows-security-noise_31bf3856ad364e35 [10.0.22621.2506] -> noise.dll
amd64_microsoft-windows-security-ntlm_31bf3856ad364e35 [10.0.22621.2715] * -> msv1_0.dll
amd64_microsoft-windows-security-ntlmshared_31bf3856ad364e35 [10.0.22621.2506] -> ntlmshared.dll
amd64_microsoft-windows-security-pku2u_31bf3856ad364e35 [10.0.22621.2715] * -> pku2u.dll
amd64_microsoft-windows-security-schannel_31bf3856ad364e35 [10.0.22621.2506] -> schannel.dll
amd64_microsoft-windows-security-spp-client_31bf3856ad364e35 [10.0.22621.2715] * -> slc.dll, sppc.dll
amd64_microsoft-windows-security-spp-clientext_31bf3856ad364e35 [10.0.22621.2715] * -> slcext.dll, sppcext.dll
amd64_microsoft-windows-security-spp-extcom_31bf3856ad364e35 [10.0.22621.2506] -> sppextcomobj.exe
amd64_microsoft-windows-security-spp-pidgenx_31bf3856ad364e35 [10.0.22621.2506] -> pidgenx.dll
amd64_microsoft-windows-security-spp-ux-dlg_31bf3856ad364e35 [10.0.22621.2506] -> changepk.exe, licensingui.exe, phoneactivate.exe, sppcommdlg.dll, upgraderesultsui.exe
amd64_microsoft-windows-security-spp-ux_31bf3856ad364e35 [10.0.22621.2506] -> devicereactivation.dll, editionupgradehelper.dll, editionupgrademanagerobj.dll, licensingwinrt.dll, slui.exe, sppcomapi.dll
amd64_microsoft-windows-security-spp_31bf3856ad364e35 [10.0.22621.2715] * -> sppmig.dll, sppsvc.exe
amd64_microsoft-windows-security-tokenbroker_31bf3856ad364e35 [10.0.22621.2506] -> tbauth.dll, tokenbroker.dll, tokenbrokercookies.exe, windows.security.authentication.web.core.dll
amd64_microsoft-windows-security-tokenbrokerui_31bf3856ad364e35 [10.0.22621.2506] -> tokenbrokerui.dll
amd64_microsoft-windows-security-tools-nltest_31bf3856ad364e35 [10.0.22621.2506] -> nltest.exe
amd64_microsoft-windows-security-tpm-engine_31bf3856ad364e35 [10.0.22621.2506] -> tpmengum.dll, tpmengum138.dll
amd64_microsoft-windows-security-vault-cds_31bf3856ad364e35 [10.0.22621.2506] -> vaultcds.dll
amd64_microsoft-windows-security-vault_31bf3856ad364e35 [10.0.22621.2506] -> vaultcli.dll, vaultsvc.dll
amd64_microsoft-windows-security-webauthn_31bf3856ad364e35 [10.0.22621.2506] -> webauthn.dll
amd64_microsoft-windows-securitycenter-core_31bf3856ad364e35 [10.0.22621.2506] -> wscadminui.exe, wscapi.dll, wscisvif.dll, wscproxystub.dll, wscsvc.dll
amd64_microsoft-windows-sendmail_31bf3856ad364e35 [10.0.22621.2506] -> sendmail.dll
amd64_microsoft-windows-sensors-core_31bf3856ad364e35 [10.0.22621.2506] -> sensorscx.dll, sensorservice.dll, sensorsnativeapi.dll, sensorsnativeapi.v2.dll, sensorsutilsv2.dll
amd64_microsoft-windows-sensors-runtimebroker_31bf3856ad364e35 [10.0.22621.2506] -> sensorruntimebroker.exe
amd64_microsoft-windows-sensors-universal_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.sensors.dll
amd64_microsoft-windows-servicing-onecore-uapi_31bf3856ad364e35 [10.0.22621.2715] * -> servicinguapi.dll
amd64_microsoft-windows-servicingcommon_31bf3856ad364e35 [10.0.22621.2506] -> servicingcommon.dll
amd64_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35 [10.0.22621.2567] -> iissetupai.dll
amd64_microsoft-windows-servicingstack-onecore_31bf3856ad364e35 [10.0.22621.2567] -> cleanupai.dll
amd64_microsoft-windows-servicingstack_31bf3856ad364e35 [10.0.22621.2567] -> cbscore.dll, cbsmsg.dll, dpx.dll, drupdate.dll, drvstore.dll, msdelta.dll, mspatcha.dll, poqexec.exe, reservemanager.dll, smiengine.dll, smipi.dll, tifilefetcher.exe, tiworker.exe, turbocontainer.dll, turbostack.dll, updateagent.dll, wcp.dll, wdscore.dll, wrpint.dll
amd64_microsoft-windows-sethc_31bf3856ad364e35 [10.0.22621.2506] -> easeofaccessdialog.exe, sethc.exe
amd64_microsoft-windows-setproxycredential_31bf3856ad364e35 [10.0.22621.2506] -> setproxycredential.dll
amd64_microsoft-windows-setup-component-logo_31bf3856ad364e35 [10.0.22621.2506] -> winlgdep.dll
amd64_microsoft-windows-setup-component_31bf3856ad364e35 [10.0.22621.2506] -> audit.exe, auditshd.exe, diager.dll, diagnostic.dll, setup.exe, spprgrss.dll, unbcl.dll, w32uiimg.dll, w32uires.dll, wdsutil.dll, win32ui.dll, winsetup.dll
amd64_microsoft-windows-setup-mbr2gpt_31bf3856ad364e35 [10.0.22621.2506] -> mbr2gpt.exe
amd64_microsoft-windows-setup360-media-base_31bf3856ad364e35 [10.0.22621.2506] -> setupprep.exe
amd64_microsoft-windows-setup360-media-onecore_31bf3856ad364e35 [10.0.22621.2715] * -> mediasetupuimgr.dll, setupcore.dll, setuphost.exe, setupmgr.dll, windlp.dll
amd64_microsoft-windows-setupapi_31bf3856ad364e35 [10.0.22621.2506] -> setupapi.dll, wowreg32.exe
amd64_microsoft-windows-setupcl-library_31bf3856ad364e35 [10.0.22621.2506] -> setupcl.dll
amd64_microsoft-windows-setupcl_31bf3856ad364e35 [10.0.22621.2506] -> setupcl.exe
amd64_microsoft-windows-sharedaccess_31bf3856ad364e35 [10.0.22621.2506] -> icsunattend.exe, ipnathlp.dll
amd64_microsoft-windows-sharedpc-sharedpccsp_31bf3856ad364e35 [10.0.22621.2506] -> sharedpccsp.dll
amd64_microsoft-windows-shcore_31bf3856ad364e35 [10.0.22621.2715] * -> shcore.dll
amd64_microsoft-windows-shdocvw_31bf3856ad364e35 [10.0.22621.2506] -> shdocvw.dll
amd64_microsoft-windows-shell-comctl32-v5_31bf3856ad364e35 [10.0.22621.2506] -> comctl32.dll
amd64_microsoft-windows-shell-customshellhost_31bf3856ad364e35 [10.0.22621.2715] * -> customshellhost.exe
amd64_microsoft-windows-shell-hub-adminflows_31bf3856ad364e35 [10.0.22621.2506] -> hubadminflows.exe, hubadminflowui.dll
amd64_microsoft-windows-shell-oobe-maintenance_31bf3856ad364e35 [10.0.22621.2506] -> oobe-maintenance.exe
amd64_microsoft-windows-shell-ppi-cleanup_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.ppi.cleanup.dll
amd64_microsoft-windows-shell-ppilogonux_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.ppi.ui.logonux.dll
amd64_microsoft-windows-shell-ppishell_31bf3856ad364e35 [10.0.22621.2715] * -> ppishell.exe, ppiui.dll
amd64_microsoft-windows-shell-setup_31bf3856ad364e35 [10.0.22621.2506] -> shsetup.dll
amd64_microsoft-windows-shell-shellappruntime_31bf3856ad364e35 [10.0.22621.2715] * -> shellappruntime.exe
amd64_microsoft-windows-shell32_31bf3856ad364e35 [10.0.22621.2506] -> shell32.dll
amd64_microsoft-windows-shellcommon-textinput_31bf3856ad364e35 [10.0.22621.2506] -> windowsinternal.composableshell.experiences.textinput.dll, windowsinternal.composableshell.experiences.textinput.layoutdata.dll
amd64_microsoft-windows-shenzhouttsvoicecommon_31bf3856ad364e35 [10.0.22621.2506] -> msttsengine.dll, msttsloc.dll
amd64_microsoft-windows-shlwapi_31bf3856ad364e35 [10.0.22621.2506] -> shlwapi.dll
amd64_microsoft-windows-shutdownux_31bf3856ad364e35 [10.0.22621.2506] -> shutdownux.dll
amd64_microsoft-windows-signalmanager_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.signals.dll
amd64_microsoft-windows-smartactionplatform_31bf3856ad364e35 [10.0.22621.2506] -> smartactionplatform.dll
amd64_microsoft-windows-smartcardksp_31bf3856ad364e35 [10.0.22621.2506] -> basecsp.dll, scksp.dll
amd64_microsoft-windows-smartcardplugins_31bf3856ad364e35 [10.0.22621.2506] -> msclmd.dll
amd64_microsoft-windows-smartcardsubsystem_31bf3856ad364e35 [10.0.22621.2506] -> scardbi.dll, scardsvr.dll
amd64_microsoft-windows-smartscreen_31bf3856ad364e35 [10.0.22621.2506] -> smartscreen.dll, smartscreen.exe, smartscreenps.dll
amd64_microsoft-windows-smartworkflows-moments_31bf3856ad364e35 [10.0.22621.2506] -> smartworkflows.dll
amd64_microsoft-windows-smb10-minirdr_31bf3856ad364e35 [10.0.22621.2506] -> mrxsmb10.sys
amd64_microsoft-windows-smb20-minirdr_31bf3856ad364e35 [10.0.22621.2506] -> mrxsmb20.sys
amd64_microsoft-windows-smbdirect_31bf3856ad364e35 [10.0.22621.2506] -> smbdirect.sys
amd64_microsoft-windows-smbminirdr_31bf3856ad364e35 [10.0.22621.2506] -> mrxsmb.sys
amd64_microsoft-windows-smbserver-apis_31bf3856ad364e35 [10.0.22621.2506] -> smbwmiv2.dll
amd64_microsoft-windows-smbserver-common_31bf3856ad364e35 [10.0.22621.2506] -> srvnet.sys
amd64_microsoft-windows-smbserver-netapi_31bf3856ad364e35 [10.0.22621.2506] -> srvcli.dll
amd64_microsoft-windows-smbserver-v1_31bf3856ad364e35 [10.0.22621.2506] -> srv.sys
amd64_microsoft-windows-smbserver-v2_31bf3856ad364e35 [10.0.22621.2506] -> srv2.sys
amd64_microsoft-windows-smbserver_31bf3856ad364e35 [10.0.22621.2506] -> srvsvc.dll, sscore.dll
amd64_microsoft-windows-smbwitnessservice-apis_31bf3856ad364e35 [10.0.22621.2506] -> witnesswmiv2provider.dll
amd64_microsoft-windows-smi-engine_31bf3856ad364e35 [10.0.22621.2506] -> smiengine.dll
amd64_microsoft-windows-spatialinteraction_31bf3856ad364e35 [10.0.22621.2506] -> spatialinteraction.dll
amd64_microsoft-windows-spb-classextension_31bf3856ad364e35 [10.0.22621.2506] -> spbcx.sys
amd64_microsoft-windows-spectrum_31bf3856ad364e35 [10.0.22621.2506] -> spectrum.exe
amd64_microsoft-windows-speech-pal-desktop_31bf3856ad364e35 [10.0.22621.2506] -> windows.speech.pal.desktop.dll
amd64_microsoft-windows-speech-shell_31bf3856ad364e35 [10.0.22621.2506] -> windows.speech.dictation.dll, windows.speech.shell.dll
amd64_microsoft-windows-speechcommon-onecore_31bf3856ad364e35 [10.0.22621.2506] -> sapi_extensions.dll, sapi_onecore.dll, speechmodeldownload.exe
amd64_microsoft-windows-speechcommon_31bf3856ad364e35 [10.0.22621.2506] -> sapi.dll
amd64_microsoft-windows-speechengine-onecore_31bf3856ad364e35 [10.0.22621.2506] -> spsreng_onecore.dll, spsrx_onecore.dll
amd64_microsoft-windows-srh_31bf3856ad364e35 [10.0.22621.2506] -> srh.dll, tier2punctuations.dll
amd64_microsoft-windows-srumon-energy_31bf3856ad364e35 [10.0.22621.2506] -> energyprov.dll
amd64_microsoft-windows-srumon-velocity_31bf3856ad364e35 [10.0.22621.2506] -> vfuprov.dll
amd64_microsoft-windows-starttiledata_31bf3856ad364e35 [10.0.22621.2506] -> datastorecachedumptool.exe, starttiledata.dll
amd64_microsoft-windows-stobject_31bf3856ad364e35 [10.0.22621.2506] -> stobject.dll
amd64_microsoft-windows-storage-diagnostics_31bf3856ad364e35 [10.0.22621.2506] -> stordiag.exe
amd64_microsoft-windows-storage-qos-filter_31bf3856ad364e35 [10.0.22621.2506] -> storqosflt.sys
amd64_microsoft-windows-storage-search-library_31bf3856ad364e35 [10.0.22621.2506] -> windows.storage.search.dll
amd64_microsoft-windows-storagemanagementwmi_31bf3856ad364e35 [10.0.22621.2506] -> delegatorprovider.dll, storagewmi.dll, storagewmi_passthru.dll
amd64_microsoft-windows-storageservice_31bf3856ad364e35 [10.0.22621.2715] * -> storageusage.dll, storsvc.dll
amd64_microsoft-windows-store-install-service_31bf3856ad364e35 [10.0.22621.2506] -> installservice.dll, installservicetasks.dll
amd64_microsoft-windows-store-licensemanager_31bf3856ad364e35 [10.0.22621.2506] -> licensemanager.dll
amd64_microsoft-windows-store-runtime_31bf3856ad364e35 [10.0.22621.2506] -> windows.applicationmodel.store.dll, windows.applicationmodel.store.testingframework.dll
amd64_microsoft-windows-storport_31bf3856ad364e35 [10.0.22621.2506] -> storport.sys
amd64_microsoft-windows-streambufferengine_31bf3856ad364e35 [10.0.22621.2506] -> sbe.dll, sbeio.dll
amd64_microsoft-windows-sud_31bf3856ad364e35 [10.0.22621.2506] -> sud.dll
amd64_microsoft-windows-switcherdatamodel_31bf3856ad364e35 [10.0.22621.2506] -> switcherdatamodel.dll
amd64_microsoft-windows-sxs_31bf3856ad364e35 [10.0.22621.2506] -> sxs.dll, sxsmigplugin.dll, sxstrace.exe
amd64_microsoft-windows-sxssrv_31bf3856ad364e35 [10.0.22621.2506] -> sxssrv.dll
amd64_microsoft-windows-syncsettings_31bf3856ad364e35 [10.0.22621.2506] -> syncsettings.dll
amd64_microsoft-windows-sysprep-spbcd_31bf3856ad364e35 [10.0.22621.2506] -> spbcd.dll
amd64_microsoft-windows-sysreset_31bf3856ad364e35 [10.0.22621.2506] -> reseteng.dll, resetengine.dll, resetengine.exe, resetengmig.dll, resetpluginhost.exe, resettelemetry.dll, sysreset.exe
amd64_microsoft-windows-systemeventsbroker_31bf3856ad364e35 [10.0.22621.2506] -> csystemeventsbrokerclient.dll, systemeventsbrokerserver.dll
amd64_microsoft-windows-systemmanagement_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.systemmanagement.dll
amd64_microsoft-windows-systemreset_31bf3856ad364e35 [10.0.22621.2506] -> reseteng.dll, resetengine.dll, resetengine.exe, resetengonline.dll, sysreseterr.exe, systemreset.exe
amd64_microsoft-windows-t..-coreinkrecognition_31bf3856ad364e35 [10.0.22621.2506] -> mshwlatin.dll
amd64_microsoft-windows-t..-deployment-package_31bf3856ad364e35 [10.0.22621.2506] -> tftp.exe
amd64_microsoft-windows-t..-deviceadminaccount_31bf3856ad364e35 [10.0.22621.2506] -> windows.team.deviceadminaccount.dll
amd64_microsoft-windows-t..-remoteapplications_31bf3856ad364e35 [10.0.22621.2506] -> rdpinit.exe, rdpshell.exe, tserrredir.dll
amd64_microsoft-windows-t..-tsappsrv-component_31bf3856ad364e35 [10.0.22621.2506] -> tsmsiprxy.dll, tsmsisrv.dll, tsvip.sys, tsvipool.dll, tsvipsrv.dll
amd64_microsoft-windows-t..alservices-webproxy_31bf3856ad364e35 [10.0.22621.2506] -> tswbprxy.exe
amd64_microsoft-windows-t..andinkinputservices_31bf3856ad364e35 [10.0.22621.2506] -> tiptsf.dll
amd64_microsoft-windows-t..atform-input-ninput_31bf3856ad364e35 [10.0.22621.2506] -> ninput.dll
amd64_microsoft-windows-t..boration-sharer-api_31bf3856ad364e35 [10.0.22621.2506] -> rdpsharercom.dll
amd64_microsoft-windows-t..ces-workspacebroker_31bf3856ad364e35 [10.0.22621.2506] -> wkspbroker.exe
amd64_microsoft-windows-t..cesframework-msctfp_31bf3856ad364e35 [10.0.22621.2506] -> msctfp.dll
amd64_microsoft-windows-t..duler-compatibility_31bf3856ad364e35 [10.0.22621.2506] -> taskcomp.dll
amd64_microsoft-windows-t..enseserver-lrwizdll_31bf3856ad364e35 [10.0.22621.2506] -> lrwizdll.dll
amd64_microsoft-windows-t..ervices-tsfairshare_31bf3856ad364e35 [10.0.22621.2506] -> rdsnetfs.dll, tsfairshare.sys
amd64_microsoft-windows-t..es-licensing-srvlic_31bf3856ad364e35 [10.0.22621.2506] -> lscshostpolicy.dll, lstelemetry.dll, tssrvlic.dll
amd64_microsoft-windows-t..es-psmgmttools-help_31bf3856ad364e35 [10.0.22621.2506] -> tspsutil.dll
amd64_microsoft-windows-t..es-workspace-radcui_31bf3856ad364e35 [10.0.22621.2506] -> radcui.dll
amd64_microsoft-windows-t..es-workspaceruntime_31bf3856ad364e35 [10.0.22621.2506] -> wksprt.exe
amd64_microsoft-windows-t..honyinteractiveuser_31bf3856ad364e35 [10.0.22621.2506] -> telephonyinteractiveuser.dll, telephonyinteractiveuserres.dll
amd64_microsoft-windows-t..icesframework-msctf_31bf3856ad364e35 [10.0.22621.2506] -> msctf.dll
amd64_microsoft-windows-t..icesframework-msutb_31bf3856ad364e35 [10.0.22621.2506] -> msutb.dll
amd64_microsoft-windows-t..lications-clientsku_31bf3856ad364e35 [10.0.22621.2506] -> rdpinit.exe, rdpshell.exe, tserrredir.dll
amd64_microsoft-windows-t..lipboardredirection_31bf3856ad364e35 [10.0.22621.2506] -> rdpclip.exe
amd64_microsoft-windows-t..lishing-wmiprovider_31bf3856ad364e35 [10.0.22621.2506] -> rdpsign.exe, tspubwmi.dll
amd64_microsoft-windows-t..localsessionmanager_31bf3856ad364e35 [10.0.22621.2506] -> lsm.dll
amd64_microsoft-windows-t..lservices-workspace_31bf3856ad364e35 [10.0.22621.2506] -> tsworkspace.dll
amd64_microsoft-windows-t..mework-msctfmonitor_31bf3856ad364e35 [10.0.22621.2506] -> msctfmonitor.dll
amd64_microsoft-windows-t..mework-uimanagerdll_31bf3856ad364e35 [10.0.22621.2506] -> msctfuimanager.dll
amd64_microsoft-windows-t..minalservicesclient_31bf3856ad364e35 [10.0.22621.2506] -> mstsc.exe
amd64_microsoft-windows-t..nalservices-runtime_31bf3856ad364e35 [10.0.22621.2506] -> winsta.dll
amd64_microsoft-windows-t..nkrecognition.ja-jp_31bf3856ad364e35 [10.0.22621.2506] -> dicjp.dll, imjplm.dll, mshwjpn.dll, mshwjpnr.dll
amd64_microsoft-windows-t..nkrecognition.ko-kr_31bf3856ad364e35 [10.0.22621.2506] -> mshwkor.dll, mshwkorr.dll
amd64_microsoft-windows-t..nkrecognition.zh-cn_31bf3856ad364e35 [10.0.22621.2506] -> mshwchs.dll, mshwchsr.dll
amd64_microsoft-windows-t..nkrecognition.zh-tw_31bf3856ad364e35 [10.0.22621.2506] -> mshwcht.dll, mshwchtr.dll
amd64_microsoft-windows-t..ormabstractionlayer_31bf3856ad364e35 [10.0.22621.2506] -> phoneplatformabstraction.dll
amd64_microsoft-windows-t..platform-comruntime_31bf3856ad364e35 [10.0.22621.2506] -> inkdiv.dll, inked.dll, inkobj.dll, rtscom.dll
amd64_microsoft-windows-t..platform-input-core_31bf3856ad364e35 [10.0.22621.2506] -> tabsvc.dll
amd64_microsoft-windows-t..putprocessor-gipdll_31bf3856ad364e35 [10.0.22621.2506] -> tsf3gip.dll
amd64_microsoft-windows-t..r-decodingresources_31bf3856ad364e35 [10.0.22621.2506] -> tdhres.dll
amd64_microsoft-windows-t..s-advanced-encoders_31bf3856ad364e35 [10.0.22621.2506] -> rdpavenc.dll
amd64_microsoft-windows-t..s-clientactivexcore_31bf3856ad364e35 [10.0.22621.2506] -> mstscax.dll, tsgqec.dll
amd64_microsoft-windows-t..s-sessionenvservice_31bf3856ad364e35 [10.0.22621.2506] -> rdvvmtransport.dll, sessenv.dll
amd64_microsoft-windows-t..sframework-inputdll_31bf3856ad364e35 [10.0.22621.2506] -> input.dll
amd64_microsoft-windows-t..teconnectionmanager_31bf3856ad364e35 [10.0.22621.2506] -> rdsdwmdr.dll, termsrv.dll
amd64_microsoft-windows-tabletpc-inputpanel_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.ink.intelligence.textinput.implementation.dll, microsoft.ink.intelligence.textinput.skill.dll, tabtip.exe, tipres.dll, tipskins.dll
amd64_microsoft-windows-tabletpc-softkeyboard_31bf3856ad364e35 [10.0.22621.2506] -> tabskb.dll
amd64_microsoft-windows-tapi3_31bf3856ad364e35 [10.0.22621.2506] -> tapi3.dll, wavemsp.dll
amd64_microsoft-windows-taskbar-dll_31bf3856ad364e35 [10.0.22621.2715] * -> taskbar.dll
amd64_microsoft-windows-taskhost_31bf3856ad364e35 [10.0.22621.2506] -> taskhostw.exe
amd64_microsoft-windows-taskscheduler-netapi_31bf3856ad364e35 [10.0.22621.2506] -> schedcli.dll
amd64_microsoft-windows-taskscheduler-service_31bf3856ad364e35 [10.0.22621.2506] -> schedsvc.dll
amd64_microsoft-windows-tcpip-driver_31bf3856ad364e35 [10.0.22621.2506] -> fwpkclnt.sys, tcpip.sys, tcpipreg.sys
amd64_microsoft-windows-tcpip-utility_31bf3856ad364e35 [10.0.22621.2506] -> arp.exe, finger.exe, hostname.exe, mrinfo.exe, netiohlp.dll, netstat.exe, route.exe, tcpsvcs.exe
amd64_microsoft-windows-tdi-over-tcpip_31bf3856ad364e35 [10.0.22621.2506] -> tdx.sys
amd64_microsoft-windows-teamos-peripherals_31bf3856ad364e35 [10.0.22621.2506] -> teamos.peripheralapi.dll, teamos.peripheralsvc.dll
amd64_microsoft-windows-telemetrypermission_31bf3856ad364e35 [10.0.22621.2506] -> diagnosticdatasettings.dll
amd64_microsoft-windows-tellib_31bf3856ad364e35 [10.0.22621.2506] -> tellib.dll
amd64_microsoft-windows-tetheringmgr_31bf3856ad364e35 [10.0.22621.2506] -> tetheringmgr.dll
amd64_microsoft-windows-tetheringstation_31bf3856ad364e35 [10.0.22621.2506] -> tetheringstation.dll
amd64_microsoft-windows-textinputframework_31bf3856ad364e35 [10.0.22621.2506] -> textinputframework.dll
amd64_microsoft-windows-themecpl_31bf3856ad364e35 [10.0.22621.2506] -> themecpl.dll
amd64_microsoft-windows-themeservice_31bf3856ad364e35 [10.0.22621.2506] -> themeservice.dll
amd64_microsoft-windows-themeui_31bf3856ad364e35 [10.0.22621.2506] -> themeui.dll
amd64_microsoft-windows-thumbnailcache_31bf3856ad364e35 [10.0.22621.2506] -> thumbcache.dll
amd64_microsoft-windows-time-ptp-provider_31bf3856ad364e35 [10.0.22621.2506] -> ptpprov.dll
amd64_microsoft-windows-time-service_31bf3856ad364e35 [10.0.22621.2506] -> w32time.dll
amd64_microsoft-windows-timezone-sync_31bf3856ad364e35 [10.0.22621.2506] -> tzsync.exe
amd64_microsoft-windows-tm_31bf3856ad364e35 [10.0.22621.2506] -> tm.sys
amd64_microsoft-windows-tpm-coreprovisioning_31bf3856ad364e35 [10.0.22621.2506] -> tpmcertresources.dll, tpmcoreprovisioning.dll
amd64_microsoft-windows-tpm-diagnostics_31bf3856ad364e35 [10.0.22621.2506] -> tpmdiagnostics.exe
amd64_microsoft-windows-tpm-tasks_31bf3856ad364e35 [10.0.22621.2715] * -> tpmtasks.dll
amd64_microsoft-windows-tpm-tbs_31bf3856ad364e35 [10.0.22621.2506] -> tbs.dll, tbs.sys
amd64_microsoft-windows-tpm-tool_31bf3856ad364e35 [10.0.22621.2506] -> tpmtool.exe
amd64_microsoft-windows-tree-classextension_31bf3856ad364e35 [10.0.22621.2506] -> windowstrustedrt.sys
amd64_microsoft-windows-trkwks_31bf3856ad364e35 [10.0.22621.2506] -> trkwks.dll
amd64_microsoft-windows-trustedinstaller_31bf3856ad364e35 [10.0.22621.2506] -> trustedinstaller.exe
amd64_microsoft-windows-tunnel_31bf3856ad364e35 [10.0.22621.2506] -> tunnel.sys
amd64_microsoft-windows-twext_31bf3856ad364e35 [10.0.22621.2506] -> twext.dll
amd64_microsoft-windows-twinapi-appcore_31bf3856ad364e35 [10.0.22621.2506] -> twinapi.appcore.dll
amd64_microsoft-windows-twinapi_31bf3856ad364e35 [10.0.22621.2506] -> twinapi.dll
amd64_microsoft-windows-twinui-appcore_31bf3856ad364e35 [10.0.22621.2506] -> twinui.appcore.dll
amd64_microsoft-windows-twinui-pcshell_31bf3856ad364e35 [10.0.22621.2715] * -> twinui.pcshell.dll
amd64_microsoft-windows-twinui_31bf3856ad364e35 [10.0.22621.2506] -> launchwinapp.exe, twinui.dll
amd64_microsoft-windows-u..-client-aggregators_31bf3856ad364e35 [10.0.22621.2506] -> aggregatorhost.exe
amd64_microsoft-windows-u..-orchestratordocked_31bf3856ad364e35 [10.0.22621.2506] -> usodocked.dll
amd64_microsoft-windows-u..access-unifiedstore_31bf3856ad364e35 [10.0.22621.2506] -> unistore.dll
amd64_microsoft-windows-u..access-userdataapis_31bf3856ad364e35 [10.0.22621.2506] -> appointmentapis.dll, chatapis.dll, contactapis.dll, emailapis.dll, peopleapis.dll, phonecallhistoryapis.dll, taskapis.dll, userdataaccountapis.dll
amd64_microsoft-windows-u..backupunitprocessor_31bf3856ad364e35 [10.0.22621.2506] -> usersettingsbackup.backupunitprocessor.dll
amd64_microsoft-windows-u..ccess-userdatautils_31bf3856ad364e35 [10.0.22621.2506] -> addressparser.dll, appointmentactivation.dll, contactactivation.dll, exsmime.dll, extrasxmlparser.dll, posyncservices.dll, userdataaccessres.dll, userdatalanguageutil.dll, userdataplatformhelperutil.dll, userdatatimeutil.dll, userdatatypehelperutil.dll, vcardparser.dll
amd64_microsoft-windows-u..ce-client-overrides_31bf3856ad364e35 [10.0.22621.2506] -> umpo-overrides.dll
amd64_microsoft-windows-u..client-core-preview_31bf3856ad364e35 [10.0.22621.2506] -> updatedeploy.dll, wuaucltcore.exe, wuauengcore.dll, wups2core.dll
amd64_microsoft-windows-u..client-decoder-host_31bf3856ad364e35 [10.0.22621.2506] -> utcdecoderhost.exe
amd64_microsoft-windows-u..cpci-classextension_31bf3856ad364e35 [10.0.22621.2506] -> ucmtcpcicx.sys
amd64_microsoft-windows-u..datesupport-preview_31bf3856ad364e35 [10.0.22621.2506] -> wuuhext.dll
amd64_microsoft-windows-u..e-ux-musscnhandlers_31bf3856ad364e35 [10.0.22621.2506] -> musdialoghandlers.dll
amd64_microsoft-windows-u..eclient-aux-preview_31bf3856ad364e35 [10.0.22621.2506] -> wuapicore.dll, wupscore.dll, wutrust.dll
amd64_microsoft-windows-u..ed-telemetry-client_31bf3856ad364e35 [10.0.22621.2506] -> diagnosticdataquery.dll, diagtrack.dll, dtdump.exe, runexehelper.exe, utcapi.dll, utcutil.dll
amd64_microsoft-windows-u..ell-sharedutilities_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.shell.sharedutilities.dll
amd64_microsoft-windows-u..em-core-classdriver_31bf3856ad364e35 [10.0.22621.2506] -> modem.sys
amd64_microsoft-windows-u..eregistration-winpe_31bf3856ad364e35 [10.0.22621.2506] -> dsreg.dll
amd64_microsoft-windows-u..ess-userdataservice_31bf3856ad364e35 [10.0.22621.2506] -> userdataservice.dll
amd64_microsoft-windows-u..ilover-core-preview_31bf3856ad364e35 [10.0.22621.2506] -> updateplatformaggregators.dll, uuscorehealthaggregator.dll, uusfailover.dll
amd64_microsoft-windows-u..lcommon-tilecontrol_31bf3856ad364e35 [10.0.22621.2506] -> tilecontrol.dll
amd64_microsoft-windows-u..ll-windowtabmanager_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.ui.shell.windowtabmanager.dll
amd64_microsoft-windows-u..mentsupport-preview_31bf3856ad364e35 [10.0.22621.2506] -> wuuhosdeployment.dll
amd64_microsoft-windows-u..mization-mi-preview_31bf3856ad364e35 [10.0.22621.2506] -> domiprov.dll
amd64_microsoft-windows-u..monotificationuxexe_31bf3856ad364e35 [10.0.22621.2506] -> monotificationux.exe
amd64_microsoft-windows-u..ountcontrolsettings_31bf3856ad364e35 [10.0.22621.2506] -> useraccountcontrolsettings.dll, useraccountcontrolsettings.exe
amd64_microsoft-windows-u..policy-core-preview_31bf3856ad364e35 [10.0.22621.2506] -> updatepolicycore.dll
amd64_microsoft-windows-u..roundprocessmanager_31bf3856ad364e35 [10.0.22621.2506] -> ubpm.dll
amd64_microsoft-windows-u..rservice-extensions_31bf3856ad364e35 [10.0.22621.2506] -> umpodev.dll, umpoext.dll
amd64_microsoft-windows-u..te-orchestratorcore_31bf3856ad364e35 [10.0.22621.2506] -> mousocoreworker.exe, usosvc.dll, usosvcimpl.dll
amd64_microsoft-windows-u..teauth-core-preview_31bf3856ad364e35 [10.0.22621.2506] -> storewuauthcore.dll
amd64_microsoft-windows-u..teelevatedinstaller_31bf3856ad364e35 [10.0.22621.2506] -> windowsupdateelevatedinstaller.exe
amd64_microsoft-windows-u..trator-core-preview_31bf3856ad364e35 [10.0.22621.2506] -> mousocoreworker.exe, usoclientimpl.dll, usosvcimpl.dll
amd64_microsoft-windows-u..ucsi-classextension_31bf3856ad364e35 [10.0.22621.2506] -> ucmucsicx.sys
amd64_microsoft-windows-u..usnotifyiconhandler_31bf3856ad364e35 [10.0.22621.2506] -> musnotifyiconhandler.dll
amd64_microsoft-windows-u..x-musupdatehandlers_31bf3856ad364e35 [10.0.22621.2506] -> musupdatehandlers.dll
amd64_microsoft-windows-u..x-musuxtoasthandler_31bf3856ad364e35 [10.0.22621.2506] -> musuxtoasthandler.dll
amd64_microsoft-windows-u..zation-core-preview_31bf3856ad364e35 [10.0.22621.2506] -> doclient.dll
amd64_microsoft-windows-ucm-classextension_31bf3856ad364e35 [10.0.22621.2506] -> ucmcx.dll, ucmcx.sys
amd64_microsoft-windows-ucrt_31bf3856ad364e35 [10.0.22621.2506] -> msvcp_win.dll, ucrtbase.dll
amd64_microsoft-windows-ucx-classextension_31bf3856ad364e35 [10.0.22621.2506] -> ucx01000.sys
amd64_microsoft-windows-udfs_31bf3856ad364e35 [10.0.22621.2506] -> udfs.sys
amd64_microsoft-windows-ui-biofeedback-library_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.biofeedback.dll
amd64_microsoft-windows-ui-cred-library_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.cred.dll
amd64_microsoft-windows-ui-fileexplorer-wasdk_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.fileexplorer.wasdk.dll
amd64_microsoft-windows-ui-fileexplorer_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.fileexplorer.dll
amd64_microsoft-windows-ui-logon-library_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.logon.dll
amd64_microsoft-windows-ui-networkuxcontroller_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.networkuxcontroller.dll
amd64_microsoft-windows-ui-pcshell_31bf3856ad364e35 [10.0.22621.2506] -> peoplebarcontainer.dll, peoplebarflyout.dll, peoplebarjumpview.dll, peoplepane.dll, shouldertapview.dll
amd64_microsoft-windows-ui-search_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.search.dll
amd64_microsoft-windows-ui-shell-component_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.shell.dll
amd64_microsoft-windows-ui-shellcommon-desktop_31bf3856ad364e35 [10.0.22621.2506] -> jumpviewui.dll, networkux.dll, peoplecommoncontrols.dll, windowsinternal.people.peoplepicker.dll
amd64_microsoft-windows-ui-shellcommoninetcore_31bf3856ad364e35 [10.0.22621.2506] -> windowsinternal.xaml.controls.tabs.dll
amd64_microsoft-windows-ui-storage_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.storage.dll
amd64_microsoft-windows-ui-xaml-controls_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xaml.controls.dll
amd64_microsoft-windows-ui-xaml-inkcontrols_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xaml.inkcontrols.dll
amd64_microsoft-windows-ui-xaml-maps_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xaml.maps.dll
amd64_microsoft-windows-ui-xaml-phone_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xaml.phone.dll
amd64_microsoft-windows-uiautomationcore_31bf3856ad364e35 [10.0.22621.2715] * -> uiautomationcore.dll
amd64_microsoft-windows-uiribbon_31bf3856ad364e35 [10.0.22621.2506] -> uiribbon.dll, uiribbonres.dll
amd64_microsoft-windows-undockeddevkit_31bf3856ad364e35 [10.0.22621.2506] -> windowsudk.shellcommon.dll, windowsudkservices.shellcommon.dll
amd64_microsoft-windows-unp_31bf3856ad364e35 [10.0.22621.2506] -> unpux.dll, unpuxhost.exe, unpuxlauncher.exe, updatenotificationhelpers.dll, updatenotificationmgr.exe
amd64_microsoft-windows-update-museuxdocked_31bf3856ad364e35 [10.0.22621.2506] -> museuxdocked.dll
amd64_microsoft-windows-update-orchestratorapi_31bf3856ad364e35 [10.0.22621.2506] -> usoapi.dll
amd64_microsoft-windows-update-uus-core_31bf3856ad364e35 [10.0.22621.2506] -> monotificationuxstub.exe, updateplatformaggregators.dll, usoclient.exe, usoclientimpl.dll, uuscorehealthaggregator.dll, uusfailover.dll
amd64_microsoft-windows-update-uus-stable_31bf3856ad364e35 [10.0.22621.2506] -> uusbrain.dll
amd64_microsoft-windows-update-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.management.update.dll
amd64_microsoft-windows-updatepolicy_31bf3856ad364e35 [10.0.22621.2506] -> updatepolicy.dll, updatepolicycore.dll
amd64_microsoft-windows-upnpdevicehost_31bf3856ad364e35 [10.0.22621.2506] -> udhisapi.dll, upnpcont.exe, upnphost.dll
amd64_microsoft-windows-upnpssdp-server_31bf3856ad364e35 [10.0.22621.2506] -> ssdpapi.dll, ssdpsrv.dll
amd64_microsoft-windows-upnpssdp_31bf3856ad364e35 [10.0.22621.2506] -> ssdpapi.dll, ssdpsrv.dll
amd64_microsoft-windows-urs-classextension_31bf3856ad364e35 [10.0.22621.2506] -> urscx01000.sys
amd64_microsoft-windows-user-choice-protection_31bf3856ad364e35 [10.0.22621.2506] -> ucpd.sys, ucpdmgr.exe
amd64_microsoft-windows-user32_31bf3856ad364e35 [10.0.22621.2506] -> user32.dll
amd64_microsoft-windows-useractivitybroker_31bf3856ad364e35 [10.0.22621.2506] -> useractivitybroker.dll
amd64_microsoft-windows-usercpl_31bf3856ad364e35 [10.0.22621.2506] -> usercpl.dll
amd64_microsoft-windows-userdeviceregistration_31bf3856ad364e35 [10.0.22621.2506] -> dsreg.dll, dsregcmd.exe, dsregtask.dll, userdeviceregistration.dll, userdeviceregistration.ngc.dll
amd64_microsoft-windows-userenv_31bf3856ad364e35 [10.0.22621.2506] -> userenv.dll
amd64_microsoft-windows-userenvext_31bf3856ad364e35 [10.0.22621.2506] -> profext.dll
amd64_microsoft-windows-userinit_31bf3856ad364e35 [10.0.22621.2506] -> userinit.exe
amd64_microsoft-windows-usermodepowerservice_31bf3856ad364e35 [10.0.22621.2506] -> umpo.dll
amd64_microsoft-windows-userpowermanagement_31bf3856ad364e35 [10.0.22621.2506] -> powrprof.dll
amd64_microsoft-windows-utilman_31bf3856ad364e35 [10.0.22621.2506] -> utilman.exe
amd64_microsoft-windows-uus-infra-core-preview_31bf3856ad364e35 [10.0.22621.2506] -> uusbrain.dll
amd64_microsoft-windows-uus-ux-common-preview_31bf3856ad364e35 [10.0.22621.2506] -> monotificationux.exe, musuxtoasthandler.dll
amd64_microsoft-windows-uus-ux-desktop-preview_31bf3856ad364e35 [10.0.22621.2506] -> musdialoghandlers.dll, musnotifyiconhandler.dll
amd64_microsoft-windows-uxinit_31bf3856ad364e35 [10.0.22621.2506] -> uxinit.dll
amd64_microsoft-windows-uxtheme_31bf3856ad364e35 [10.0.22621.2506] -> uxtheme.dll
amd64_microsoft-windows-v..e-filters-tvdigital_31bf3856ad364e35 [10.0.22621.2506] -> psisdecd.dll
amd64_microsoft-windows-v..lient-wmiv2provider_31bf3856ad364e35 [10.0.22621.2506] -> vpnclientpsprovider.dll
amd64_microsoft-windows-v..model-tilemigration_31bf3856ad364e35 [10.0.22621.2506] -> tdlmigration.dll
amd64_microsoft-windows-v..payloadrestrictions_31bf3856ad364e35 [10.0.22621.2506] -> payloadrestrictions.dll
amd64_microsoft-windows-van_31bf3856ad364e35 [10.0.22621.2506] -> van.dll
amd64_microsoft-windows-video-for-windows_31bf3856ad364e35 [10.0.22621.2506] -> avicap32.dll, avifil32.dll, mciavi32.dll, msrle32.dll, msvfw32.dll, msvidc32.dll
amd64_microsoft-windows-vidproc_31bf3856ad364e35 [10.0.22621.2506] -> msvproc.dll
amd64_microsoft-windows-virtualdiskapilibrary_31bf3856ad364e35 [10.0.22621.2506] -> convertvhd.exe, virtdisk.dll
amd64_microsoft-windows-virtualdiskservice_31bf3856ad364e35 [10.0.22621.2506] -> vds.exe, vds_ps.dll, vdsldr.exe, vdsutil.dll
amd64_microsoft-windows-virtualmonitormanager_31bf3856ad364e35 [10.0.22621.2506] -> virtualmonitormanager.dll
amd64_microsoft-windows-voiceaccessstub_31bf3856ad364e35 [10.0.22621.2506] -> voiceaccess.exe
amd64_microsoft-windows-volsnap_31bf3856ad364e35 [10.0.22621.2506] -> volsnap.sys
amd64_microsoft-windows-w..-chinese_simplified_31bf3856ad364e35 [10.0.22621.2506] -> mswb70804.dll, nl7data0804.dll
amd64_microsoft-windows-w..-infrastructure-bsp_31bf3856ad364e35 [10.0.22621.2506] -> mswsock.dll
amd64_microsoft-windows-w..-system-diagnostics_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.diagnostics.dll
amd64_microsoft-windows-w..ationservice-netapi_31bf3856ad364e35 [10.0.22621.2506] -> wkscli.dll
amd64_microsoft-windows-w..chinese_traditional_31bf3856ad364e35 [10.0.22621.2506] -> mswb70404.dll, nl7data0404.dll
amd64_microsoft-windows-w..dateclient-api-host_31bf3856ad364e35 [10.0.22621.2506] -> wuapihost.exe
amd64_microsoft-windows-w..driverupdatesupport_31bf3856ad364e35 [10.0.22621.2506] -> wuuhdrv.dll
amd64_microsoft-windows-w..ebviewhost.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> win32webviewhost.exe
amd64_microsoft-windows-w..emassessmenttoolapi_31bf3856ad364e35 [10.0.22621.2506] -> winsatapi.dll
amd64_microsoft-windows-w..erplaydvddiagnostic_31bf3856ad364e35 [10.0.22621.2506] -> diagpackage.dll
amd64_microsoft-windows-w..for-management-core_31bf3856ad364e35 [10.0.22621.2506] -> wsmagent.dll, wsmanhttpconfig.exe, wsmanmigrationplugin.dll, wsmauto.dll, wsmplpxy.dll, wsmprovhost.exe, wsmres.dll, wsmsvc.dll, wsmwmipl.dll
amd64_microsoft-windows-w..ialibrarydiagnostic_31bf3856ad364e35 [10.0.22621.2506] -> diagpackage.dll
amd64_microsoft-windows-w..ig-registrar-wizard_31bf3856ad364e35 [10.0.22621.2506] -> wcnwiz.dll
amd64_microsoft-windows-w..igurationdiagnostic_31bf3856ad364e35 [10.0.22621.2506] -> diagpackage.dll
amd64_microsoft-windows-w..indowsuiinputinking_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.input.inking.dll
amd64_microsoft-windows-w..iodatamodel-library_31bf3856ad364e35 [10.0.22621.2506] -> winbiodatamodel.dll, winbiodatamodeloobe.exe
amd64_microsoft-windows-w..nt-extupdatesupport_31bf3856ad364e35 [10.0.22621.2506] -> wuuhext.dll
amd64_microsoft-windows-w..ommand-line-utility_31bf3856ad364e35 [10.0.22621.2506] -> wmic.exe
amd64_microsoft-windows-w..osdeploymentsupport_31bf3856ad364e35 [10.0.22621.2506] -> wuuhosdeployment.dll
amd64_microsoft-windows-w..ovider-cimwin32-dll_31bf3856ad364e35 [10.0.22621.2506] -> cimwin32.dll
amd64_microsoft-windows-w..owsupdateclient-aux_31bf3856ad364e35 [10.0.22621.2506] -> wuapi.dll, wuapicore.dll, wups.dll, wupscore.dll, wusys.dll, wutrust.dll
amd64_microsoft-windows-w..r7-mswb7ea-japanese_31bf3856ad364e35 [10.0.22621.2506] -> mswb70011.dll, nl7data0011.dll
amd64_microsoft-windows-w..sition-coreservices_31bf3856ad364e35 [10.0.22621.2506] -> esclwiadriver.dll, sti.dll, wiarpc.dll, wiaservc.dll, wiatrace.dll
amd64_microsoft-windows-w..utinking-inkobjcore_31bf3856ad364e35 [10.0.22621.2506] -> inkobjcore.dll
amd64_microsoft-windows-w..wsupdateclient-core_31bf3856ad364e35 [10.0.22621.2506] -> updatedeploy.dll, wuauclt.exe, wuaucltcore.exe, wuaueng.dll, wuauengcore.dll, wups2.dll, wups2core.dll
amd64_microsoft-windows-w..ystemassessmenttool_31bf3856ad364e35 [10.0.22621.2506] -> winsat.exe
amd64_microsoft-windows-waasmedic_31bf3856ad364e35 [10.0.22621.2506] -> waasmedicagent.exe, waasmediccapsule.dll, waasmedicps.dll, waasmedicsvc.dll, waasmedicsvcimpl.dll, windows.internal.waasmedicdocked.dll
amd64_microsoft-windows-wab-core_31bf3856ad364e35 [10.0.22621.2506] -> wab32.dll, wab32res.dll, wabimp.dll
amd64_microsoft-windows-watchdog_31bf3856ad364e35 [10.0.22621.2506] -> watchdog.sys
amd64_microsoft-windows-wbiosrvc_31bf3856ad364e35 [10.0.22621.2506] -> wbiosrvc.dll
amd64_microsoft-windows-wcmsvc_31bf3856ad364e35 [10.0.22621.2506] -> cellulardatacapabilityhandler.dll, wcmcsp.dll, wcmsvc.dll, wifidatacapabilityhandler.dll
amd64_microsoft-windows-wdf-kernellibrary_31bf3856ad364e35 [10.0.22621.2506] -> wdf01000.sys, wdfldr.sys
amd64_microsoft-windows-wdf-usermodelibrary_31bf3856ad364e35 [10.0.22621.2506] -> wudfx02000.dll
amd64_microsoft-windows-web-app-host-api_31bf3856ad364e35 [10.0.22621.2506] -> wwaapi.dll
amd64_microsoft-windows-web-app-host_31bf3856ad364e35 [10.0.22621.2506] -> wwahost.exe
amd64_microsoft-windows-web-http_31bf3856ad364e35 [10.0.22621.2506] -> windows.web.http.dll
amd64_microsoft-windows-webio_31bf3856ad364e35 [10.0.22621.2506] -> webio.dll
amd64_microsoft-windows-webp-image-codec_31bf3856ad364e35 [10.0.22621.2506] -> mswebp.dll
amd64_microsoft-windows-webview2standalone_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.web.webview2.core.dll, webview2standalone.dll
amd64_microsoft-windows-wer-sdktools_31bf3856ad364e35 [10.0.22621.2506] -> dbgeng.dll, dbgmodel.dll
amd64_microsoft-windows-wfdsconmgr_31bf3856ad364e35 [10.0.22621.2506] -> wfdsconmgr.dll, wfdsconmgrsvc.dll
amd64_microsoft-windows-wifi-classextension_31bf3856ad364e35 [10.0.22621.2506] -> wificx.sys
amd64_microsoft-windows-wificloudstore_31bf3856ad364e35 [10.0.22621.2506] -> wificloudstore.dll
amd64_microsoft-windows-wifidisplay_31bf3856ad364e35 [10.0.22621.2506] -> wifidisplay.dll
amd64_microsoft-windows-wifinetworkmanager_31bf3856ad364e35 [10.0.22621.2506] -> wifinetworkmanager.dll, wifitask.exe
amd64_microsoft-windows-wimgapi_31bf3856ad364e35 [10.0.22621.2506] -> wimgapi.dll, wimmount.sys, wimserv.exe
amd64_microsoft-windows-win32k_31bf3856ad364e35 [10.0.22621.2506] -> win32k.sys, win32kfull.sys, win32u.dll
amd64_microsoft-windows-win32kbase_31bf3856ad364e35 [10.0.22621.2506] -> win32kbase.sys
amd64_microsoft-windows-win32ksgd_31bf3856ad364e35 [10.0.22621.2506] -> win32ksgd.sys
amd64_microsoft-windows-wincredui_31bf3856ad364e35 [10.0.22621.2506] -> wincredui.dll
amd64_microsoft-windows-windlp-inbox_31bf3856ad364e35 [10.0.22621.2715] * -> windlp.dll
amd64_microsoft-windows-windowscodec_31bf3856ad364e35 [10.0.22621.2506] -> windowscodecs.dll
amd64_microsoft-windows-windowsstorage-onecore_31bf3856ad364e35 [10.0.22621.2506] -> windows.storage.onecore.dll
amd64_microsoft-windows-windowsuiimmersive_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.immersive.dll
amd64_microsoft-windows-windowui_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.dll
amd64_microsoft-windows-wininit_31bf3856ad364e35 [10.0.22621.2506] -> wininit.exe, wmsgapi.dll
amd64_microsoft-windows-winlogon-ext_31bf3856ad364e35 [10.0.22621.2506] -> winlogonext.dll
amd64_microsoft-windows-winlogon_31bf3856ad364e35 [10.0.22621.2506] -> winlogon.exe
amd64_microsoft-windows-winmde_31bf3856ad364e35 [10.0.22621.2506] -> winmde.dll
amd64_microsoft-windows-winnat_31bf3856ad364e35 [10.0.22621.2506] -> winnat.sys
amd64_microsoft-windows-winquic_31bf3856ad364e35 [10.0.22621.2506] -> msquic.sys
amd64_microsoft-windows-winre-recoveryagent_31bf3856ad364e35 [10.0.22621.2506] -> reagent.dll, reinfo.dll
amd64_microsoft-windows-winre-recoverytools_31bf3856ad364e35 [10.0.22621.2506] -> reagentc.exe
amd64_microsoft-windows-winre-tools_31bf3856ad364e35 [10.0.22621.2506] -> bootrec.exe, recenv.exe, startrep.exe
amd64_microsoft-windows-winreagent_31bf3856ad364e35 [10.0.22621.2506] -> winreagent.dll
amd64_microsoft-windows-winrecfg_31bf3856ad364e35 [10.0.22621.2506] -> winrecfg.exe
amd64_microsoft-windows-winrt-metadata_31bf3856ad364e35 [10.0.22621.2506] -> rometadata.dll
amd64_microsoft-windows-winrt-windowsgraphics_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.dll
amd64_microsoft-windows-winsock-core_31bf3856ad364e35 [10.0.22621.2506] -> afd.sys
amd64_microsoft-windows-winsrvext_31bf3856ad364e35 [10.0.22621.2506] -> winsrvext.dll
amd64_microsoft-windows-wintrust-dll_31bf3856ad364e35 [10.0.22621.2506] -> wintrust.dll
amd64_microsoft-windows-wlanconnectionflow_31bf3856ad364e35 [10.0.22621.2506] -> wlanconn.dll
amd64_microsoft-windows-wlangpui_31bf3856ad364e35 [10.0.22621.2506] -> wlangpui.dll
amd64_microsoft-windows-wlanmediamanager_31bf3856ad364e35 [10.0.22621.2506] -> wlanmm.dll
amd64_microsoft-windows-wmadmod_31bf3856ad364e35 [10.0.22621.2506] -> wmadmod.dll
amd64_microsoft-windows-wmi-core-fastprox-dll_31bf3856ad364e35 [10.0.22621.2506] -> fastprox.dll
amd64_microsoft-windows-wmi-core-wbemcomn-dll_31bf3856ad364e35 [10.0.22621.2506] -> wbemcomn.dll
amd64_microsoft-windows-wmi-core-wbemcore-dll_31bf3856ad364e35 [10.0.22621.2506] -> wbemcore.dll
amd64_microsoft-windows-wmi-core_31bf3856ad364e35 [10.0.22621.2506] -> esscli.dll, framedynos.dll, mofcomp.exe, mofd.dll, ncobjapi.dll, ncprov.dll, unsecapp.exe, wbemprox.dll, wbemsvc.dll, winmgmtr.dll, wmiadap.exe, wmiapres.dll, wmiapsrv.exe, wmicookr.dll, wmimigrationplugin.dll, wmiutils.dll
amd64_microsoft-windows-wmpnss-api_31bf3856ad364e35 [10.0.22621.2506] -> wmpnssci.dll
amd64_microsoft-windows-wmpnss-publicapi_31bf3856ad364e35 [10.0.22621.2506] -> wmpmediasharing.dll
amd64_microsoft-windows-wmpnss-service_31bf3856ad364e35 [10.0.22621.2506] -> wmpnetwk.exe
amd64_microsoft-windows-wmpnss-ux_31bf3856ad364e35 [10.0.22621.2506] -> wmpnscfg.exe
amd64_microsoft-windows-wmspdmod_31bf3856ad364e35 [10.0.22621.2506] -> wmspdmod.dll
amd64_microsoft-windows-wmvdecod_31bf3856ad364e35 [10.0.22621.2506] -> wmvdecod.dll
amd64_microsoft-windows-wmviddsp_31bf3856ad364e35 [10.0.22621.2506] -> colorcnv.dll, vidreszr.dll
amd64_microsoft-windows-wordpad_31bf3856ad364e35 [10.0.22621.2506] -> wordpad.exe, wordpadfilter.dll
amd64_microsoft-windows-workplace_31bf3856ad364e35 [10.0.22621.2506] -> windows.management.workplace.dll
amd64_microsoft-windows-workstationservice_31bf3856ad364e35 [10.0.22621.2506] -> wkssvc.dll
amd64_microsoft-windows-wow64-console_31bf3856ad364e35 [10.0.22621.2506] -> wow64con.dll
amd64_microsoft-windows-wow64-windows_31bf3856ad364e35 [10.0.22621.2506] -> wow64win.dll
amd64_microsoft-windows-wow64_31bf3856ad364e35 [10.0.22621.2506] -> wow64.dll, wow64base.dll, wow64cpu.dll
amd64_microsoft-windows-wpd-busenumservice_31bf3856ad364e35 [10.0.22621.2506] -> wpdbusenum.dll
amd64_microsoft-windows-wpd-shellextension_31bf3856ad364e35 [10.0.22621.2715] * -> wpdshext.dll, wpdshextautoplay.exe, wpdshserviceobj.dll
amd64_microsoft-windows-wpprecorderum_31bf3856ad364e35 [10.0.22621.2506] -> wpprecorderum.dll
amd64_microsoft-windows-wrp-integrity-client_31bf3856ad364e35 [10.0.22621.2506] -> sfc.exe
amd64_microsoft-windows-wsp-fileserver_31bf3856ad364e35 [10.0.22621.2506] -> wsp_fs.dll
amd64_microsoft-windows-wsp-health_31bf3856ad364e35 [10.0.22621.2506] -> wsp_health.dll
amd64_microsoft-windows-wsp-replication_31bf3856ad364e35 [10.0.22621.2506] -> wsp_sr.dll
amd64_microsoft-windows-wsp-spaces_31bf3856ad364e35 [10.0.22621.2506] -> mispace.dll, smphost.dll
amd64_microsoft-windows-wvr-cimprovider_31bf3856ad364e35 [10.0.22621.2506] -> wvrcimprov.dll
amd64_microsoft-windows-wvr-ps-cmdlets_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.fileservices.sr.powershell.dll
amd64_microsoft-windows-wwan-lpa-api_31bf3856ad364e35 [10.0.22621.2506] -> windows.networking.networkoperators.esim.dll
amd64_microsoft-windows-wwan-lpacsp_31bf3856ad364e35 [10.0.22621.2506] -> euiccscsp.dll
amd64_microsoft-windows-wwan-lpasvc_31bf3856ad364e35 [10.0.22621.2506] -> lpasvc.dll
amd64_microsoft-windows-wwansvc_31bf3856ad364e35 [10.0.22621.2506] -> knetpwrdepbroker.sys, wwanprotdim.dll, wwansvc.dll
amd64_microsoft-windows-x..jectdialog.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> xgpuejectdialog.exe
amd64_microsoft-windows-x..rtificateenrollment_31bf3856ad364e35 [10.0.22621.2506] -> certenroll.dll, certenrollctrl.exe
amd64_microsoft-windows-xamlhost-library_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xamlhost.dll
amd64_microsoft-windows-xmllite_31bf3856ad364e35 [10.0.22621.2506] -> xmllite.dll
amd64_microsoft-windows-xpsifilter_31bf3856ad364e35 [10.0.22621.2506] -> xpsfilt.dll
amd64_microsoft-windows-xpsreachviewer_31bf3856ad364e35 [10.0.22621.2506] -> xpsrchvw.exe
amd64_microsoft-windows-zipfldr_31bf3856ad364e35 [10.0.22621.2715] * -> zipfldr.dll
amd64_microsoft-windowsco..etwork-flowsteering_31bf3856ad364e35 [10.0.22621.2506] -> fse.sys
amd64_microsoft-windowscore-coreglobconfig_31bf3856ad364e35 [10.0.22621.2506] -> coreglobconfig.dll
amd64_microsoft-windowsphone-ufx_31bf3856ad364e35 [10.0.22621.2506] -> ufx01000.sys
amd64_microsoft-xbox-auth..er-client-component_31bf3856ad364e35 [10.0.22621.2506] -> xblauthmanagerproxy.dll, xblauthtokenbrokerext.dll
amd64_microsoft-xbox-authmanager-component_31bf3856ad364e35 [10.0.22621.2506] -> xblauthmanager.dll
amd64_microsoft-xbox-gamecallableui.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> gamingtcuihelpers.dll, microsoft.diagnostics.tracing.eventsource.dll, xbox.tcui.exe, xbox.tcui.resource.dll, xbox.tcui.shell.dll, xbox.tcui.tracing.dll, xboxexperienceservices.dll
amd64_microsoft-xbox-gameoverlay_31bf3856ad364e35 [10.0.22621.2506] -> gamepanel.exe, gamepanelexternalhook.dll
amd64_microsoft-xbox-gipmanagement-component_31bf3856ad364e35 [10.0.22621.2506] -> xboxgipsvc.dll
amd64_microsoft.appv.appvclientcomconsumer_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.appv.appvclientcomconsumer.dll
amd64_microsoft.backgroun..r.management.module_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.backgroundintelligenttransfer.management.interop.dll
amd64_microsoft.certifica..s.pkiclient.cmdlets_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.certificateservices.pkiclient.cmdlets.dll
amd64_microsoft.configci.commands.resources_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.configci.commands.resources.dll
amd64_microsoft.configci.commands_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.configci.commands.dll
amd64_microsoft.grouppolicy.admtmpleditor_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.grouppolicy.admtmpleditor.dll
amd64_microsoft.grouppolicy.interop_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.grouppolicy.interop.dll
amd64_microsoft.grouppolicy.management.interop_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.grouppolicy.management.interop.dll
amd64_microsoft.grouppolicy.targeting.interop_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.grouppolicy.targeting.interop.dll
amd64_microsoft.keydistributionservice.cmdlets_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.keydistributionservice.cmdlets.dll
amd64_microsoft.processmitigations.commands_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.processmitigations.commands.dll
amd64_microsoft.virtualiz..ent.rdpclientaxhost_31bf3856ad364e35 [10.0.22621.2715] * -> microsoft.virtualization.client.rdpclientaxhost.dll
amd64_microsoft.virtualiz..nt.rdpclientinterop_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.virtualization.client.rdpclientinterop.dll
amd64_microsoft.windows.common-controls_6595b64144ccf1df [6.0.22621.2506] -> comctl32.dll
amd64_microsoft.windows.dsc.core_31bf3856ad364e35 [10.0.22621.2506] -> dsccore.dll
amd64_microsoft.windows.gdiplus.systemcopy_31bf3856ad364e35 [10.0.22621.2506] -> gdiplus.dll
amd64_microsoft.windows.gdiplus_6595b64144ccf1df [1.1.22621.2506] -> gdiplus.dll
amd64_microsoft.windows.h..uetooth-driverclass_31bf3856ad364e35 [10.0.22621.2506] -> bthci.dll
amd64_microsoft.windows.s..ermanager.rdsplugin_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.servermanager.rdsplugin.dll, rdmsinst.dll, rdmsres.dll, tspubiconhelper.dll
amd64_microsoft.windows.winhttp_31bf3856ad364e35 [5.1.22621.2506] -> pacjsworker.exe, winhttp.dll
amd64_microsoft.windowsau..nprotocols.commands_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windowsauthenticationprotocols.commands.dll
amd64_multimedia-windows-..rotection-playready_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.protection.playready.dll
amd64_multipoint-wms.controls_31bf3856ad364e35 [10.0.22621.2506] -> wms.controls.dll
amd64_multipoint-wms.nativeutilities_31bf3856ad364e35 [10.0.22621.2506] -> wms.nativeutilities.dll
amd64_multipoint-wmstoastapi_31bf3856ad364e35 [10.0.22621.2506] -> wmstoastapi.dll
amd64_napcrypt_31bf3856ad364e35 [10.0.22621.2506] -> napcrypt.dll
amd64_networking-mpssvc-admin.resources_31bf3856ad364e35 [10.0.22621.2506] -> authfwsnapin.resources.dll, authfwwizfwk.resources.dll
amd64_networking-mpssvc-admin_31bf3856ad364e35 [10.0.22621.2506] -> authfwgp.dll, authfwsnapin.dll, authfwwizfwk.dll
amd64_networking-mpssvc-drv_31bf3856ad364e35 [10.0.22621.2506] -> mpsdrv.sys
amd64_networking-mpssvc-netsh_31bf3856ad364e35 [10.0.22621.2506] -> authfwcfg.dll, checknetisolation.exe, fwcfg.dll, nshwfp.dll
amd64_networking-mpssvc-p..l-windows.resources_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.firewall.commands.resources.dll
amd64_networking-mpssvc-powershell-windows_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.firewall.commands.dll
amd64_networking-mpssvc-svc_31bf3856ad364e35 [10.0.22621.2506] -> firewallapi.dll, fwbase.dll, fwpolicyiomgr.dll, icfupgd.dll, mpssvc.dll, wfapigp.dll
amd64_networking-mpssvc-wmi_31bf3856ad364e35 [10.0.22621.2506] -> wfascim.dll
amd64_ppi-ppiskype-c-a_31bf3856ad364e35 [10.0.22621.2506] -> appsharingmediaproviderimm.dll, clientlib.dll, clientppi.dll, clrcompression.dll, concrt140_app.dll, csiimm.dll, lyncimmres.dll, microsoft.applications.telemetry.windows.dll, microsoft.foundation.diagnostics.dll, microsoft.internal.propertymodel.dll, microsoft.internal.propertymodel.proxy.dll, microsoft.lync.propertymodel.dll, microsoft.lync.propertyviewmodel.dll, microsoft.lyncimm.viewmodel.dll, microsoft.ppiskype.viewmodels.dll, microsoft.ppiskype.windows.exe, microsoft.rtc.winrt.mmvr.mediaengine.dll, microsoft.skype.joinlinkdiscovery.dll, microsoft.skypeteam.applayer.dll, microsoft.skypeteam.nativeconverters.dll, microsoft.skypeteam.nativeutils.dll, microsoft.skypeteam.nativeview.dll, microsoft.skypeteam.telemetry.dll, microsoft.windows.ppiskype.dll, microsoft.windows.ppiskype.exe, mrt100_app.dll, mso20imm.dll, mso30imm.dll, mso40uiimm.dll, mso50imm.dll, mso98imm.dll, msoidclim.dll, msoimm.dll, msointlimm.dll, msvcp120_app.dll, msvcp140_app.dll, msvcr120_app.dll, ocapiresimm.dll, ocpptviewstub.dll, office.ui.xaml.core.dll, psomimm.dll, roottools.dll, rtmcodecs.dll, rtmmediamanager.dll, rtmpal.dll, rtmpltfm.dll, ssscreenvvs2.dll, toastnotificationbackgroundtask.dll, uccapiimm.dll, ucimm.dll, ucmsgqueue.dll, vcamp120_app.dll, vcamp140_app.dll, vccorlib120_app.dll, vccorlib140_app.dll, vcomp120_app.dll, vcomp140_app.dll, vcruntime140_app.dll
amd64_product-containeros..x-deployment-server_31bf3856ad364e35 [10.0.22621.2715] * -> appinstallerbackgroundupdate.exe, applytrustoffline.exe, appxapplicabilityblob.dll, appxdeploymentextensions.desktop.dll, appxdeploymentextensions.onecore.dll, appxdeploymentserver.dll, appxupgrademigrationplugin.dll, custominstallexec.exe
amd64_product-containeros__windowssearchengine_31bf3856ad364e35 [7.0.22621.2506] -> msscntrs.dll, mssitlb.dll, mssph.dll, mssprxy.dll, mssrch.dll, mssvp.dll, search.protocolhandler.mapi2.dll, searchfilterhost.exe, searchindexer.exe, searchindexercore.dll, searchprotocolhost.exe, tquery.dll, wsearchmigplugin.dll
amd64_product-onecore__du.._avrcptransport.inf_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.bluetooth.avrcptransport.sys
amd64_product-onecore__du.._bluetooth_a2dp.inf_31bf3856ad364e35 [10.0.22621.2506] -> btha2dp.sys
amd64_product-onecore__du..t_bluetooth_hfp.inf_31bf3856ad364e35 [10.0.22621.2506] -> bthhfaud.sys, bthhfenum.sys
amd64_product-onecore__dual_apxunit.inf_31bf3856ad364e35 [10.0.22621.2506] -> apxunit.sys
amd64_product-onecore__dual_hdaudbus.inf_31bf3856ad364e35 [10.0.22621.2506] -> hdaudbus.sys
amd64_product-onecore__dual_hdaudio.inf_31bf3856ad364e35 [10.0.22621.2506] -> hdaudio.sys
amd64_product-onecore__dual_usbxhci.inf_31bf3856ad364e35 [10.0.22621.2506] -> usbxhci.sys
amd64_product-onecore__dual_wdmaudio.inf_31bf3856ad364e35 [10.0.22621.2506] -> drmk.sys, drmkaud.sys, msapofxproxy.dll, portcls.sys
amd64_product-onecore__mi..-workstationservice_31bf3856ad364e35 [10.0.22621.2506] -> wkssvc.dll
amd64_product-onecore__mi..ft-windows-wmspdmod_31bf3856ad364e35 [10.0.22621.2506] -> wmspdmod.dll
amd64_product-onecore__mi..ft-windows-wmvdecod_31bf3856ad364e35 [10.0.22621.2506] -> wmvdecod.dll
amd64_product-onecore__mi..ndows-mfmpeg2srcsnk_31bf3856ad364e35 [10.0.22621.2715] * -> mfmpeg2srcsnk.dll
amd64_product-onecore__mi..oft-windows-wmadmod_31bf3856ad364e35 [10.0.22621.2506] -> wmadmod.dll
amd64_product-onecore__mi..onentpackagesupport_31bf3856ad364e35 [10.0.22621.2506] -> comppkgsrv.exe, comppkgsup.dll
amd64_product-onecore__mi..r-v-socket-provider_31bf3856ad364e35 [10.0.22621.2506] -> hvsocket.sys
amd64_product-onecore__mi..soft-windows-mfcore_31bf3856ad364e35 [10.0.22621.2715] * -> mfcore.dll, mfps.dll
amd64_product-onecore__mi..tartup-filterdriver_31bf3856ad364e35 [10.0.22621.2506] -> dumpfve.sys, fvevol.sys
amd64_product-onecore__mi..windows-mfasfsrcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfasfsrcsnk.dll
amd64_product-onecore__mi..windows-msauddecmft_31bf3856ad364e35 [10.0.22621.2506] -> msauddecmft.dll
amd64_product-onecore__mi..windows-msmpeg2vdec_31bf3856ad364e35 [10.0.22621.2715] * -> msmpeg2vdec.dll
amd64_security-octagon-agent_31bf3856ad364e35 [10.0.22621.2506] -> sgrmagent.sys
amd64_security-octagon-broker_31bf3856ad364e35 [10.0.22621.2506] -> sgrmbroker.exe, sgrmlpac.exe
amd64_security-octagon-clientapi_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.security.attestation.deviceattestation.dll
amd64_security-octagon-enclave_31bf3856ad364e35 [10.0.22621.2506] -> sgrmenclave.dll, sgrmenclave_secure.dll
amd64_serviceinitiatedhealing-client_31bf3856ad364e35 [10.0.22621.2506] -> sihclient.exe
amd64_tenantrestrictions-plugin_31bf3856ad364e35 [10.0.22621.2506] -> tenantrestrictionsplugin.dll
amd64_umb_31bf3856ad364e35 [10.0.22621.2506] -> umb.dll
amd64_universalvolumecontrol-model_31bf3856ad364e35 [10.0.22621.2506] -> uvcmodel.dll
amd64_userexperience-core_31bf3856ad364e35 [10.0.22621.2506] -> adaptivecards.objectmodel.uwp.dll, adaptivecards.rendering.uwp.dll, backupbanner.dll, concrt140_app.dll, fileexplorerextensions.dll, msvcp140_1_app.dll, msvcp140_2_app.dll, msvcp140_app.dll, msvcp140_atomic_wait_app.dll, msvcp140_codecvt_ids_app.dll, snaplayout.dll, startmenu.dll, taskbar.view.dll, vcamp140_app.dll, vccorlib140_app.dll, vcomp140_app.dll, vcruntime140_1_app.dll, vcruntime140_app.dll
amd64_userexperience-desktop_31bf3856ad364e35 [10.0.22621.2506] -> accountsservice.dll, applistbackup.dll, commandexecutor.dll, desktopspotlight.dll, desktopstickereditor.dll, desktopstickereditorwin32exe.exe, desktopvisual.dll, experienceextensions.dll, fesearchhost.exe, freuserinterface.dll, hermes.dll, inputapp.dll, irisservice.dll, layoutdata.dll, livecaptions.dll, livecaptionsbackend.dll, livecaptionsdesktop.dll, livecaptionsxamlapplication.dll, logonwebhost.dll, logonwebhostproduct.exe, microsoft.cognitiveservices.speech.core.dll, microsoft.cognitiveservices.speech.extension.audio.sys.dll, microsoft.cognitiveservices.speech.extension.embedded.sr.dll, microsoft.cognitiveservices.speech.extension.embedded.sr.runtime.dll, microsoft.cognitiveservices.speech.extension.embedded.tts.dll, microsoft.cognitiveservices.speech.extension.lu.dll, microsoft.cognitiveservices.speech.extension.onnxruntime.dll, microsoft.cognitiveservices.speech.extension.telemetry.dll, microsoft.reactnative.dll, microsoftgraphrecentitemsmanager.dll, minisearchhost.exe, payments.dll, reactnativexaml.dll, rulesengine.dll, screenclipping.dll, screenclippinghost.exe, searchhost.exe, searchux.core.dll, searchux.internalwebapi.dll, searchux.miniui.dll, searchux.model.dll, searchux.ui.dll, searchux.webapi.dll, smartactionsux.dll, speechrecognizer.dll, speechsynthesizerextension.dll, systemsettingsextensions.dll, textinput.carbondictation.dll, textinput.dictationui.dll, textinput.dll, textinputcommon.dll, textinputextensions.dll, textinputhost.exe, usersetup.eligibility.dll, ux-phui.dll, voiceaccess.dll, voiceaccesscommon.dll, voiceaccesshost.dll, voiceaccessuserinterface.dll, webexperiencehost.dll, webexperiencehostapp.exe, windowsbackup.dll, windowsbackupclient.exe, windowsinternal.composableshell.experiences.suggestionuiundocked.dll, winrtcomponents.dll, winrtturbomodule.dll, wsxpackmanager.dll, wv2winrt.dll
amd64_userexperience-fileexp_31bf3856ad364e35 [10.0.22621.2506] -> fileexplorerextensions.dll
amd64_userexperience-hub_31bf3856ad364e35 [10.0.22621.2506] -> concrt140_app.dll, inputapp.dll, layoutdata.dll, microsoft.cognitiveservices.speech.core.dll, microsoft.cognitiveservices.speech.extension.audio.sys.dll, microsoft.cognitiveservices.speech.extension.embedded.sr.dll, microsoft.cognitiveservices.speech.extension.embedded.sr.runtime.dll, microsoft.cognitiveservices.speech.extension.embedded.tts.dll, microsoft.cognitiveservices.speech.extension.lu.dll, microsoft.cognitiveservices.speech.extension.onnxruntime.dll, msvcp140_1_app.dll, msvcp140_2_app.dll, msvcp140_app.dll, msvcp140_atomic_wait_app.dll, msvcp140_codecvt_ids_app.dll, smartactionsux.dll, snaplayout.dll, startmenu.dll, textinput.carbondictation.dll, textinput.dictationui.dll, textinput.dll, textinputcommon.dll, textinputextensions.dll, textinputhost.exe, vcamp140_app.dll, vccorlib140_app.dll, vcomp140_app.dll, vcruntime140_1_app.dll, vcruntime140_app.dll, windowsinternal.composableshell.experiences.suggestionuiundocked.dll
amd64_winappsdk-cbs_31bf3856ad364e35 [10.0.22621.2715] * -> coremessagingxp.dll, dcompi.dll, deploymentagent.exe, dwmcorei.dll, dwmscenei.dll, dwritecore.dll, marshal.dll, microsoft.directmanipulation.dll, microsoft.graphics.display.dll, microsoft.inputstatemanager.dll, microsoft.internal.frameworkudk.cbs.dll, microsoft.internal.frameworkudk.dll, microsoft.ui.composition.ossupport.dll, microsoft.ui.dll, microsoft.ui.input.dll, microsoft.ui.windowing.core.dll, microsoft.ui.windowing.dll, microsoft.ui.xaml.controls.dll, microsoft.ui.xaml.dll, microsoft.ui.xaml.internal.dll, microsoft.ui.xaml.phone.dll, microsoft.ui.xaml.resources.19h1.dll, microsoft.ui.xaml.resources.common.dll, microsoft.web.webview2.core.dll, microsoft.windows.applicationmodel.resources.dll, microsoft.windows.widgets.dll, microsoft.windowsappruntime.bootstrap.dll, microsoft.windowsappruntime.dll, microsoft.windowsappruntime.insights.resource.dll, mrm.dll, pushnotificationslongrunningtask.proxystub.dll, restartagent.exe, windowsappsdk.appxdeploymentextensions.desktop-eventlog-instrumentation.dll, winuiedit.dll, wuceffectsi.dll
amd64_windows-application..-appcontracts-winrt_31bf3856ad364e35 [10.0.22621.2506] -> appcontracts.dll
amd64_windows-application..egistrationverifier_31bf3856ad364e35 [10.0.22621.2506] -> apphostregistrationverifier.exe
amd64_windows-applicationmodel-clipboardserver_31bf3856ad364e35 [10.0.22621.2506] -> clipboardserver.dll
amd64_windows-applicationmodel_31bf3856ad364e35 [10.0.22621.2506] -> windows.applicationmodel.dll
amd64_windows-gaming-input-synthetic_31bf3856ad364e35 [10.0.22621.2506] -> xboxgipsynthetic.dll
amd64_windows-gaming-input-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.gaming.input.dll, xinputuap.dll
amd64_windows-gaming-xbox..e-service-component_31bf3856ad364e35 [10.0.22621.2506] -> xblgamesave.dll, xblgamesavetask.exe
amd64_windows-id-connecte..-provider-tokenprov_31bf3856ad364e35 [10.0.22621.2506] -> microsoftaccounttokenprovider.dll
amd64_windows-id-connecte..nt-provider-activex_31bf3856ad364e35 [10.0.22621.2506] -> windowslivelogin.dll
amd64_windows-id-connecte..nt-provider-wlidcli_31bf3856ad364e35 [10.0.22621.2506] -> wlidcli.dll
amd64_windows-id-connecte..nt-provider-wlidfdp_31bf3856ad364e35 [10.0.22621.2506] -> wlidfdp.dll
amd64_windows-id-connecte..nt-provider-wlidnsp_31bf3856ad364e35 [10.0.22621.2506] -> wlidnsp.dll
amd64_windows-id-connecte..nt-provider-wlidsvc_31bf3856ad364e35 [10.0.22621.2506] -> wlidsvc.dll
amd64_windows-id-connecte..ovider-wlidcredprov_31bf3856ad364e35 [10.0.22621.2506] -> wlidcredprov.dll
amd64_windows-id-connecte..t-provider-wlidprov_31bf3856ad364e35 [10.0.22621.2506] -> wlidprov.dll
amd64_windows-media-speech-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.speech.dll, windows.media.speech.uxres.dll
amd64_windows-seccoredriver_31bf3856ad364e35 [10.0.22621.2506] -> msseccore.sys
amd64_windows-secdriver_31bf3856ad364e35 [10.0.22621.2715] * -> mssecflt.sys, mssecuser.dll
amd64_windows-securityhealth-sso_31bf3856ad364e35 [10.0.22621.2506] -> securityhealthsso.dll, securityhealthssoudk.dll, securityhealthsystray.exe
amd64_windows-secwfpdriver_31bf3856ad364e35 [10.0.22621.2506] -> mssecwfp.sys, mssecwfpu.dll
amd64_windows-senseclient-mdm_31bf3856ad364e35 [10.0.22621.2506] -> watpcsp.dll
amd64_windows-senseclient-service_31bf3856ad364e35 [10.0.22621.2715] * -> aadrt.dll, mce.dll, mpgear.dll, mssense.dll, mssense.exe, mswb70011.dll, mswb70404.dll, mswb70804.dll, nl7data0011.dll, nl7data0404.dll, nl7data0804.dll, opctextextractorwin.dll, runpsscript.dll, senseaadauthenticator.exe, sensece.exe, sensecm.exe, sensegpparser.exe, senseimdscollector.exe, senseir.exe, sensemirror.dll, sensendr.exe, sensesampleuploader.exe, sensetvm.exe
amd64_windows-shield-provider_31bf3856ad364e35 [10.0.22621.2506] -> securityhealthagent.dll, securityhealthcore.dll, securityhealthhost.exe, securityhealthproxystub.dll, securityhealthservice.exe, securityhealthudk.dll
amd64_windows-staterepository_31bf3856ad364e35 [10.0.22621.2506] -> staterepository.core.dll, windows.staterepository.dll, windows.staterepositorybroker.dll, windows.staterepositoryclient.dll, windows.staterepositorycore.dll, windows.staterepositoryps.dll, windows.staterepositoryupgrade.dll
amd64_windows-system-launcher_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.launcher.dll
amd64_windows-system-prof..ndusagedatasettings_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.profile.platformdiagnosticsandusagedatasettings.dll
amd64_windows-system-user..diagnosticssettings_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.userprofile.diagnosticssettings.dll
amd64_windows.networking.vpn.csp_31bf3856ad364e35 [10.0.22621.2506] -> vpnv2csp.dll
amd64_windows.networking.vpn_31bf3856ad364e35 [10.0.22621.2506] -> cmintegrator.dll, windows.networking.vpn.dll
amd64_windowsdeviceportal-core-server_31bf3856ad364e35 [10.0.22621.2506] -> webmanagement.exe
amd64_windowsdeviceportal-optional-powerplugin_31bf3856ad364e35 [10.0.22621.2506] -> windowsdeviceportal.powerplugin.dll
amd64_windowsdeviceportal-userservice_31bf3856ad364e35 [10.0.22621.2506] -> webmanagementuser.dll
amd64_windowsdeviceportal..erceptionsimulation_31bf3856ad364e35 [10.0.22621.2506] -> perceptionsimulationrest.dll
amd64_windowsdeviceportal..ional-devicesplugin_31bf3856ad364e35 [10.0.22621.2506] -> windowsdeviceportal.devicesplugin.dll
amd64_windowsdeviceportal..l-spatialmapmanager_31bf3856ad364e35 [10.0.22621.2506] -> windowsdeviceportal.spatialmapmanager.dll
amd64_windowsdeviceportal..onal-locationplugin_31bf3856ad364e35 [10.0.22621.2506] -> windowsdeviceportal.locationplugin.dll
amd64_windowsdeviceportal..onal-usb4viewplugin_31bf3856ad364e35 [10.0.22621.2506] -> windowsdeviceportal.usb4viewplugin.dll
amd64_windowsdeviceportal..onal-xboxliveplugin_31bf3856ad364e35 [10.0.22621.2506] -> windowsdeviceportal.xboxliveplugin.dll
amd64_windowsdeviceportal..oolsplugin.appxmain_31bf3856ad364e35 [10.0.22621.2506] -> edgedevtoolsprotocol.dll
amd64_windowsdeviceportal_31bf3856ad364e35 [10.0.22621.2506] -> wdp.dll
amd64_windowssearchengine-structuredquery_31bf3856ad364e35 [7.0.22621.2506] -> structuredquery.dll
amd64_windowssearchengine_31bf3856ad364e35 [7.0.22621.2506] -> msscntrs.dll, mssitlb.dll, mssph.dll, mssprxy.dll, mssrch.dll, mssvp.dll, search.protocolhandler.mapi2.dll, searchfilterhost.exe, searchindexer.exe, searchindexercore.dll, searchprotocolhost.exe, tquery.dll, wsearchmigplugin.dll
msil_microsoft.appv.appvclientwmi_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.appv.appvclientwmi.dll
msil_microsoft.grouppoli..reporting.resources_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.grouppolicy.reporting.resources.dll
msil_microsoft.grouppolicy.reporting_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.grouppolicy.reporting.dll
msil_microsoft.powershell.commands.management_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.powershell.commands.management.dll
msil_microsoft.powershell.commands.utility_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.powershell.commands.utility.dll
msil_microsoft.security...agement.policymodel_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.security.applicationid.policymanagement.policymodel.dll
msil_microsoft.updateservices.baseapi_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.updateservices.baseapi.dll
msil_microsoft.web.management.iisclient_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.web.management.iisclient.dll
msil_microsoft.windows.d..mmands.getdiaginput_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.diagnosis.commands.getdiaginput.dll
msil_microsoft.windows.diagnosis.sdhost_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.diagnosis.sdhost.dll
msil_microsoft.windows.dsc.coreconfproviders_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.dsc.coreconfproviders.dll
msil_microsoft.windows.f..nt.plugin.resources_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.fileserver.management.plugin.resources.dll
msil_microsoft.windows.f..r.management.plugin_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.fileserver.management.plugin.dll
msil_microsoft.windows.s..nager.hyperv.plugin_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.servermanager.hyperv.plugin.dll
msil_system.management.automation.resources_31bf3856ad364e35 [10.0.22621.2506] -> system.management.automation.resources.dll
msil_system.management.automation_31bf3856ad364e35 [10.0.22621.2506] -> system.management.automation.dll
wow64_bsdtar_31bf3856ad364e35 [10.0.22621.2506] -> tar.exe
wow64_curl_31bf3856ad364e35 [10.0.22621.2715] * -> curl.exe
wow64_desktop_shell-search-srchadmin_31bf3856ad364e35 [7.0.22621.2506] -> srchadmin.dll
wow64_dsprop_31bf3856ad364e35 [10.0.22621.2506] -> dsprop.dll
wow64_fdssdp_31bf3856ad364e35 [10.0.22621.2506] -> fdssdp.dll
wow64_hyperv-ux-featurestaging_31bf3856ad364e35 [10.0.22621.2506] -> vmstaging.dll
wow64_libarchive-internal_31bf3856ad364e35 [10.0.22621.2506] -> archiveint.dll
wow64_microsoft-gaming-ga..rnal-presencewriter_31bf3856ad364e35 [10.0.22621.2506] -> gamebarpresencewriter.exe, gamebarpresencewriter.proxy.dll
wow64_microsoft-onecore-a..ecore-onecore-other_31bf3856ad364e35 [10.0.22621.2506] -> midimap.dll, msacm32.drv
wow64_microsoft-onecore-a..nmodel-datatransfer_31bf3856ad364e35 [10.0.22621.2506] -> windows.applicationmodel.datatransfer.dll
wow64_microsoft-onecore-a..sibility-experience_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.accessibility.dll
wow64_microsoft-onecore-bluetooth-proxy_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.bluetooth.proxy.dll
wow64_microsoft-onecore-bluetooth-userapis_31bf3856ad364e35 [10.0.22621.2506] -> bluetoothapis.dll, wshbth.dll
wow64_microsoft-onecore-c..dexperiencehost-api_31bf3856ad364e35 [10.0.22621.2506] -> cloudexperiencehostcommon.dll
wow64_microsoft-onecore-c..experiencehost-user_31bf3856ad364e35 [10.0.22621.2506] -> cloudexperiencehostuser.dll
wow64_microsoft-onecore-c..ilityaccess-manager_31bf3856ad364e35 [10.0.22621.2506] -> capabilityaccessmanagerclient.dll
wow64_microsoft-onecore-c..rivacysettingsstore_31bf3856ad364e35 [10.0.22621.2506] -> coreprivacysettingsstore.dll
wow64_microsoft-onecore-cdp-winrt_31bf3856ad364e35 [10.0.22621.2715] * -> cdprt.dll
wow64_microsoft-onecore-console-host-propsheet_31bf3856ad364e35 [10.0.22621.2506] -> console.dll
wow64_microsoft-onecore-coremessaging_31bf3856ad364e35 [10.0.22621.2506] -> coremessaging.dll
wow64_microsoft-onecore-d..ent-dmapisetexthost_31bf3856ad364e35 [10.0.22621.2506] -> dmapisetextimpl.dll
wow64_microsoft-onecore-d..onmanager-component_31bf3856ad364e35 [10.0.22621.2506] -> dictationmanager.dll
wow64_microsoft-onecore-d..rectxdatabasehelper_31bf3856ad364e35 [10.0.22621.2506] -> directxdatabasehelper.dll
wow64_microsoft-onecore-directx-dxcore_31bf3856ad364e35 [10.0.22621.2506] -> dxcore.dll
wow64_microsoft-onecore-dusm-api_31bf3856ad364e35 [10.0.22621.2506] -> dusmapi.dll
wow64_microsoft-onecore-gameinput_31bf3856ad364e35 [10.0.22621.2506] -> gameinput.dll
wow64_microsoft-onecore-l..languageoverlayutil_31bf3856ad364e35 [10.0.22621.2506] -> languageoverlayutil.dll
wow64_microsoft-onecore-m..imedia-broadcastdvr_31bf3856ad364e35 [10.0.22621.2506] -> bcastdvr.proxy.dll, bcastdvrbroker.dll, bcastdvrclient.dll, bcastdvrcommon.dll
wow64_microsoft-onecore-m..lnamespaceextension_31bf3856ad364e35 [10.0.22621.2715] * -> dlnashext.dll
wow64_microsoft-onecore-networkprofile-common_31bf3856ad364e35 [10.0.22621.2506] -> netprofm.dll, npmproxy.dll
wow64_microsoft-onecore-p..evicemanagement-rtl_31bf3856ad364e35 [10.0.22621.2506] -> devobj.dll, devrtl.dll
wow64_microsoft-onecore-pickerplatform_31bf3856ad364e35 [10.0.22621.2506] -> pickerplatform.dll
wow64_microsoft-onecore-pnp-devicemanagement_31bf3856ad364e35 [10.0.22621.2506] -> cfgmgr32.dll
wow64_microsoft-onecore-pnp-drvsetup_31bf3856ad364e35 [10.0.22621.2506] -> drvsetup.dll
wow64_microsoft-onecore-s..chservice-component_31bf3856ad364e35 [10.0.22621.2506] -> speechservicewinrtapi.proxystub.dll
wow64_microsoft-onecore-sharehost_31bf3856ad364e35 [10.0.22621.2506] -> sharehost.dll
wow64_microsoft-onecore-tetheringservice_31bf3856ad364e35 [10.0.22621.2506] -> tetheringclient.dll
wow64_microsoft-onecore-tiledatarepository_31bf3856ad364e35 [10.0.22621.2506] -> tiledatarepository.dll
wow64_microsoft-onecore-uiamanager_31bf3856ad364e35 [10.0.22621.2506] -> uiamanager.dll
wow64_microsoft-onecore-w..river-client-sensor_31bf3856ad364e35 [10.0.22621.2506] -> wtdsensor.dll
wow64_microsoft-onecore-w..se-clipboardmonitor_31bf3856ad364e35 [10.0.22621.2506] -> wtdccm.dll
wow64_microsoft-onecore-windowmanagementapi_31bf3856ad364e35 [10.0.22621.2506] -> windowmanagementapi.dll
wow64_microsoft-onecoreuap-deviceaccess_31bf3856ad364e35 [10.0.22621.2506] -> deviceaccess.dll
wow64_microsoft-system-user-component_31bf3856ad364e35 [10.0.22621.2506] -> usermgrproxy.dll
wow64_microsoft-textinput-helpers_31bf3856ad364e35 [10.0.22621.2506] -> ime_textinputhelpers.dll
wow64_microsoft-webdriver-server-components_31bf3856ad364e35 [10.0.22621.2506] -> microsoftwebdriver.exe
wow64_microsoft-windows-3daudio-hrtfapo_31bf3856ad364e35 [10.0.22621.2506] -> hrtfapo.dll, hrtfdspcpu.dll, ssdm.dll, virtualsurroundapo.dll
wow64_microsoft-windows-a..-experience-apphelp_31bf3856ad364e35 [10.0.22621.2506] -> apphlpdm.dll, pcaui.exe
wow64_microsoft-windows-a..-messagingdatamodel_31bf3856ad364e35 [10.0.22621.2506] -> messagingdatamodel2.dll
wow64_microsoft-windows-a..appvprogrammability_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.appv.appvclientcomconsumer.dll, microsoft.appv.appvclientpowershell.dll, microsoft.appv.appvclientwmi.dll, microsoft.appv.clientprogrammability.eventing.dll
wow64_microsoft-windows-a..bility-assistant-ui_31bf3856ad364e35 [10.0.22621.2506] -> pcacli.dll, pcaui.dll
wow64_microsoft-windows-a..bility-ui-recording_31bf3856ad364e35 [10.0.22621.2506] -> uireng.dll
wow64_microsoft-windows-a..cationmodel-daxexec_31bf3856ad364e35 [10.0.22621.2506] -> daxexec.dll
wow64_microsoft-windows-a..dcredentialprovider_31bf3856ad364e35 [10.0.22621.2506] -> smartcardcredentialprovider.dll
wow64_microsoft-windows-a..ence-infrastructure_31bf3856ad364e35 [10.0.22621.2506] -> apphelp.dll, sdbinst.exe, shimeng.dll
wow64_microsoft-windows-a..ence-inventory-core_31bf3856ad364e35 [10.0.22621.2506] -> aepic.dll
wow64_microsoft-windows-a..ence-mitigations-c3_31bf3856ad364e35 [10.0.22621.2506] -> acgenral.dll
wow64_microsoft-windows-a..ence-mitigations-c5_31bf3856ad364e35 [10.0.22621.2506] -> aclayers.dll, acxtrnal.dll
wow64_microsoft-windows-a..ionmodel-lockscreen_31bf3856ad364e35 [10.0.22621.2506] -> windows.applicationmodel.lockscreen.dll
wow64_microsoft-windows-a..l-appexecutionalias_31bf3856ad364e35 [10.0.22621.2506] -> apisethost.appexecutionalias.dll
wow64_microsoft-windows-a..o-mmecore-winmmbase_31bf3856ad364e35 [10.0.22621.2506] -> winmm.dll
wow64_microsoft-windows-a..on-authui-component_31bf3856ad364e35 [10.0.22621.2506] -> authui.dll
wow64_microsoft-windows-a..on-experience-tools_31bf3856ad364e35 [10.0.22621.2506] -> acppage.dll
wow64_microsoft-windows-a..one-updater-service_31bf3856ad364e35 [10.0.22621.2506] -> tzautoupdate.dll
wow64_microsoft-windows-aarsvc_31bf3856ad364e35 [10.0.22621.2506] -> aarsvc.dll, agentactivationruntime.dll, agentactivationruntimestarter.exe, agentactivationruntimewindows.dll, windows.applicationmodel.conversationalagent.dll, windows.applicationmodel.conversationalagent.internal.proxystub.dll, windows.applicationmodel.conversationalagent.proxystub.dll
wow64_microsoft-windows-accessibilitycpl_31bf3856ad364e35 [10.0.22621.2506] -> accessibilitycpl.dll
wow64_microsoft-windows-accountscontrol-api_31bf3856ad364e35 [10.0.22621.2506] -> windows.accountscontrol.dll
wow64_microsoft-windows-aclui_31bf3856ad364e35 [10.0.22621.2506] -> aclui.dll
wow64_microsoft-windows-activationmanager_31bf3856ad364e35 [10.0.22621.2506] -> activationmanager.dll
wow64_microsoft-windows-activexproxy_31bf3856ad364e35 [10.0.22621.2506] -> actxprxy.dll
wow64_microsoft-windows-advancedtaskmanager_31bf3856ad364e35 [10.0.22621.2506] -> launchtm.exe, taskmanagerdatalayer.dll, taskmgr.exe
wow64_microsoft-windows-advapi32_31bf3856ad364e35 [10.0.22621.2715] * -> advapi32.dll
wow64_microsoft-windows-alljoyn-api_31bf3856ad364e35 [10.0.22621.2506] -> msajapi.dll
wow64_microsoft-windows-appid_31bf3856ad364e35 [10.0.22621.2506] -> appidapi.dll
wow64_microsoft-windows-appidcore_31bf3856ad364e35 [10.0.22621.2506] -> appidtel.exe, applockercsp.dll, srpapi.dll
wow64_microsoft-windows-appmanagement-appvwow_31bf3856ad364e35 [10.0.22621.2506] -> appvclientps.dll, appvdllsurrogate.exe, appventsubsystems32.dll, appvsentinel.dll, appvterminator.dll, mavinject.exe
wow64_microsoft-windows-appmanagement-uevpsmof_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.uev.agentwmi.dll, microsoft.uev.commands.dll
wow64_microsoft-windows-appmanagement-uevwow_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.uev.appagent.dll, microsoft.uev.office2010customactions.dll, microsoft.uev.office2013customactions.dll
wow64_microsoft-windows-appresolver_31bf3856ad364e35 [10.0.22621.2506] -> appresolver.dll
wow64_microsoft-windows-appwiz_31bf3856ad364e35 [10.0.22621.2506] -> appwiz.cpl
wow64_microsoft-windows-appx-alluserstore_31bf3856ad364e35 [10.0.22621.2506] -> appxalluserstore.dll
wow64_microsoft-windows-appx-deployment-client_31bf3856ad364e35 [10.0.22621.2506] -> appxdeploymentclient.dll
wow64_microsoft-windows-appxsip_31bf3856ad364e35 [10.0.22621.2506] -> appxsip.dll
wow64_microsoft-windows-at_31bf3856ad364e35 [10.0.22621.2506] -> at.exe
wow64_microsoft-windows-atbroker_31bf3856ad364e35 [10.0.22621.2506] -> atbroker.exe
wow64_microsoft-windows-audio-audiocore-client_31bf3856ad364e35 [10.0.22621.2506] -> audioses.dll
wow64_microsoft-windows-audio-audiocore_31bf3856ad364e35 [10.0.22621.2506] -> audioeng.dll, audiokse.dll, coremas.dll, remoteaudioendpoint.dll, spatialaudiolicensesrv.exe
wow64_microsoft-windows-audio-dmusic_31bf3856ad364e35 [10.0.22621.2506] -> dmloader.dll, dmsynth.dll, dmusic.dll, dswave.dll
wow64_microsoft-windows-audio-dsound_31bf3856ad364e35 [10.0.22621.2506] -> dsdmo.dll, dsound.dll
wow64_microsoft-windows-audio-volumecontrol_31bf3856ad364e35 [10.0.22621.2506] -> sndvol.exe, sndvolsso.dll
wow64_microsoft-windows-authext_31bf3856ad364e35 [10.0.22621.2506] -> authext.dll
wow64_microsoft-windows-autochk_31bf3856ad364e35 [10.0.22621.2506] -> autochk.exe
wow64_microsoft-windows-b..-configuration-data_31bf3856ad364e35 [10.0.22621.2506] -> bcd.dll
wow64_microsoft-windows-b..infrastructurewinrt_31bf3856ad364e35 [10.0.22621.2506] -> biwinrt.dll
wow64_microsoft-windows-b..re-memorydiagnostic_31bf3856ad364e35 [10.0.22621.2506] -> memtest.exe
wow64_microsoft-windows-basic-misc-tools_31bf3856ad364e35 [10.0.22621.2506] -> netmsg.dll
wow64_microsoft-windows-batmeter_31bf3856ad364e35 [10.0.22621.2506] -> batmeter.dll
wow64_microsoft-windows-bcp47languages_31bf3856ad364e35 [10.0.22621.2506] -> bcp47langs.dll, bcp47mrm.dll
wow64_microsoft-windows-bcrypt-dll_31bf3856ad364e35 [10.0.22621.2506] -> bcrypt.dll
wow64_microsoft-windows-bcrypt-primitives-dll_31bf3856ad364e35 [10.0.22621.2506] -> bcryptprimitives.dll
wow64_microsoft-windows-branding-engine_31bf3856ad364e35 [10.0.22621.2506] -> winbrand.dll, winsku.dll
wow64_microsoft-windows-browserservice-netapi_31bf3856ad364e35 [10.0.22621.2506] -> browcli.dll
wow64_microsoft-windows-bth-cpl_31bf3856ad364e35 [10.0.22621.2506] -> bthprops.cpl
wow64_microsoft-windows-bth-user_31bf3856ad364e35 [10.0.22621.2506] -> bluetoothopppushclient.dll, bthudtask.exe, fsquirt.exe
wow64_microsoft-windows-c..-joinprovideronline_31bf3856ad364e35 [10.0.22621.2506] -> joinproviderol.dll
wow64_microsoft-windows-c..-radiomediaprovider_31bf3856ad364e35 [10.0.22621.2506] -> bthradiomedia.dll
wow64_microsoft-windows-c..alproviders-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovs.dll
wow64_microsoft-windows-c..atemanagersnapindll_31bf3856ad364e35 [10.0.22621.2506] -> certmgr.dll
wow64_microsoft-windows-c..bluetooth-telemetry_31bf3856ad364e35 [10.0.22621.2506] -> bthtelemetry.dll
wow64_microsoft-windows-c..cn-config-registrar_31bf3856ad364e35 [10.0.22621.2506] -> wcnapi.dll
wow64_microsoft-windows-c..complus-eventsystem_31bf3856ad364e35 [10.0.22621.2506] -> es.dll
wow64_microsoft-windows-c..complus-runtime-qfe_31bf3856ad364e35 [10.0.22621.2506] -> catsrv.dll, clbcatq.dll, colbact.dll
wow64_microsoft-windows-c..dtc-runtime-cluster_31bf3856ad364e35 [10.0.22621.2506] -> mtxclu.dll
wow64_microsoft-windows-c..ent-appxpackagingom_31bf3856ad364e35 [10.0.22621.2506] -> appxpackaging.dll
wow64_microsoft-windows-c..ent-indexing-common_31bf3856ad364e35 [10.0.22621.2506] -> query.dll
wow64_microsoft-windows-c..esources-deployment_31bf3856ad364e35 [10.0.22621.2506] -> mrmdeploy.dll
wow64_microsoft-windows-c..esources-mrmindexer_31bf3856ad364e35 [10.0.22621.2506] -> mrmindexer.dll
wow64_microsoft-windows-c..fe-catsrvut-comsvcs_31bf3856ad364e35 [10.0.22621.2506] -> catsrvut.dll, comsvcs.dll
wow64_microsoft-windows-c..gureexpandedstorage_31bf3856ad364e35 [10.0.22621.2506] -> configureexpandedstorage.dll
wow64_microsoft-windows-c..iderslegacy-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovslegacy.dll
wow64_microsoft-windows-c..onentpackagesupport_31bf3856ad364e35 [10.0.22621.2506] -> comppkgsup.dll
wow64_microsoft-windows-c..ov2fahelper-library_31bf3856ad364e35 [10.0.22621.2506] -> credprov2fahelper.dll
wow64_microsoft-windows-c..ovdatamodel-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovdatamodel.dll
wow64_microsoft-windows-c..provision-framework_31bf3856ad364e35 [10.0.22621.2506] -> netprovfw.dll
wow64_microsoft-windows-c..rymanager-utilities_31bf3856ad364e35 [10.0.22621.2506] -> contentdeliverymanager.utilities.dll
wow64_microsoft-windows-c..services-certca-dll_31bf3856ad364e35 [10.0.22621.2506] -> certca.dll
wow64_microsoft-windows-c..t-resources-mrmcore_31bf3856ad364e35 [10.0.22621.2506] -> mrmcorer.dll
wow64_microsoft-windows-c..t-xpsomandstreaming_31bf3856ad364e35 [10.0.22621.2506] -> xpspushlayer.dll, xpsservices.dll
wow64_microsoft-windows-c..tem-tracedatahelper_31bf3856ad364e35 [10.0.22621.2506] -> tdh.dll
wow64_microsoft-windows-c..tionauthorityclient_31bf3856ad364e35 [10.0.22621.2506] -> certcli.dll
wow64_microsoft-windows-c..tprovision-joinutil_31bf3856ad364e35 [10.0.22621.2506] -> joinutil.dll
wow64_microsoft-windows-c..urces-applicability_31bf3856ad364e35 [10.0.22621.2506] -> appxapplicabilityengine.dll
wow64_microsoft-windows-cabinet_31bf3856ad364e35 [10.0.22621.2506] -> cabinet.dll
wow64_microsoft-windows-cabview_31bf3856ad364e35 [10.0.22621.2506] -> cabview.dll
wow64_microsoft-windows-cdp-api_31bf3856ad364e35 [10.0.22621.2715] * -> cdp.dll
wow64_microsoft-windows-certificaterequesttool_31bf3856ad364e35 [10.0.22621.2506] -> certreq.exe
wow64_microsoft-windows-certutil_31bf3856ad364e35 [10.0.22621.2506] -> certenc.dll, certutil.exe
wow64_microsoft-windows-ci-wldp-dll_31bf3856ad364e35 [10.0.22621.2506] -> wldp.dll
wow64_microsoft-windows-cloudfiles-apilibrary_31bf3856ad364e35 [10.0.22621.2506] -> cldapi.dll
wow64_microsoft-windows-cloudnotifications_31bf3856ad364e35 [10.0.22621.2506] -> cloudnotifications.exe
wow64_microsoft-windows-cmisetup_31bf3856ad364e35 [10.0.22621.2506] -> cmisetup.dll
wow64_microsoft-windows-com-base-qfe-ole32_31bf3856ad364e35 [10.0.22621.2506] -> ole32.dll
wow64_microsoft-windows-com-base_31bf3856ad364e35 [10.0.22621.2506] -> combase.dll, wincorlib.dll, wintypes.dll
wow64_microsoft-windows-com-coml2_31bf3856ad364e35 [10.0.22621.2506] -> coml2.dll
wow64_microsoft-windows-com-dtc-client_31bf3856ad364e35 [10.0.22621.2506] -> msdtcprx.dll, msdtcspoffln.dll, xolehlp.dll
wow64_microsoft-windows-com-dtc-management-ui_31bf3856ad364e35 [10.0.22621.2506] -> msdtcuiu.dll
wow64_microsoft-windows-com-dtc-management-wmi_31bf3856ad364e35 [10.0.22621.2506] -> msdtcwmi.dll
wow64_microsoft-windows-com-dtc-setup_31bf3856ad364e35 [10.0.22621.2506] -> msdtcstp.dll
wow64_microsoft-windows-com-oleui_31bf3856ad364e35 [10.0.22621.2506] -> oledlg.dll
wow64_microsoft-windows-comdlg32_31bf3856ad364e35 [10.0.22621.2506] -> comdlg32.dll
wow64_microsoft-windows-commandprompt_31bf3856ad364e35 [10.0.22621.2506] -> cmd.exe
wow64_microsoft-windows-component-opcom_31bf3856ad364e35 [10.0.22621.2506] -> opcservices.dll
wow64_microsoft-windows-computer-name-ui_31bf3856ad364e35 [10.0.22621.2506] -> netid.dll
wow64_microsoft-windows-consolelogon-library_31bf3856ad364e35 [10.0.22621.2506] -> consolelogon.dll
wow64_microsoft-windows-containers-library_31bf3856ad364e35 [10.0.22621.2506] -> container.dll
wow64_microsoft-windows-coreinkrecognition_31bf3856ad364e35 [10.0.22621.2506] -> mshwrwisp.dll, mshwstaging.dll
wow64_microsoft-windows-coreshellapi_31bf3856ad364e35 [10.0.22621.2506] -> coreshellapi.dll
wow64_microsoft-windows-coresystem-wpr_31bf3856ad364e35 [10.0.22621.2506] -> windowsperformancerecordercontrol.dll
wow64_microsoft-windows-coreuicomponents_31bf3856ad364e35 [10.0.22621.2506] -> coreuicomponents.dll
wow64_microsoft-windows-creddialogcontroller_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.creddialogcontroller.dll
wow64_microsoft-windows-credprovhelper-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovhelper.dll
wow64_microsoft-windows-credprovhost-library_31bf3856ad364e35 [10.0.22621.2506] -> credprovhost.dll
wow64_microsoft-windows-credui-onecore_31bf3856ad364e35 [10.0.22621.2506] -> credui.dll
wow64_microsoft-windows-credwiz_31bf3856ad364e35 [10.0.22621.2506] -> credwiz.exe
wow64_microsoft-windows-crypt32-dll_31bf3856ad364e35 [10.0.22621.2506] -> crypt32.dll
wow64_microsoft-windows-cryptsp-dll_31bf3856ad364e35 [10.0.22621.2506] -> cryptsp.dll
wow64_microsoft-windows-crypttpmeksvc-dll_31bf3856ad364e35 [10.0.22621.2506] -> crypttpmeksvc.dll
wow64_microsoft-windows-cryptui-dll_31bf3856ad364e35 [10.0.22621.2506] -> cryptui.dll
wow64_microsoft-windows-d..-charcodedictionary_31bf3856ad364e35 [10.0.22621.2506] -> imjpcd.dll
wow64_microsoft-windows-d..-eashared-imebroker_31bf3856ad364e35 [10.0.22621.2506] -> imebrokerps.dll
wow64_microsoft-windows-d..-externaldictionary_31bf3856ad364e35 [10.0.22621.2506] -> imewdbld.exe
wow64_microsoft-windows-d..-japanese-lmprofile_31bf3856ad364e35 [10.0.22621.2506] -> imjplmp.dll
wow64_microsoft-windows-d..-japanese-migration_31bf3856ad364e35 [10.0.22621.2506] -> imjpmig.dll
wow64_microsoft-windows-d..-japanese-nameinput_31bf3856ad364e35 [10.0.22621.2506] -> imjpcmld.dll
wow64_microsoft-windows-d..-japanese-utilities_31bf3856ad364e35 [10.0.22621.2506] -> imjpdct.exe, imjpdctp.dll, imjpuex.exe
wow64_microsoft-windows-d..-mmc-usersandgroups_31bf3856ad364e35 [10.0.22621.2506] -> localsec.dll
wow64_microsoft-windows-d..-warp-jitexecutable_31bf3856ad364e35 [10.0.22621.2506] -> windows.warp.jitservice.exe
wow64_microsoft-windows-d..-winproviders-image_31bf3856ad364e35 [10.0.22621.2506] -> cbsprovider.dll, dmiprovider.dll, genericprovider.dll, intlprovider.dll, offlinesetupprovider.dll, osprovider.dll, provprovider.dll, smiprovider.dll, unattendprovider.dll
wow64_microsoft-windows-d..-winproviders-local_31bf3856ad364e35 [10.0.22621.2506] -> ffuprovider.dll, imagingprovider.dll, vhdprovider.dll, wimprovider.dll
wow64_microsoft-windows-d..anager-unenrollhook_31bf3856ad364e35 [10.0.22621.2506] -> unenrollhook.dll
wow64_microsoft-windows-d..andlinepropertytool_31bf3856ad364e35 [10.0.22621.2506] -> imjpuexc.exe
wow64_microsoft-windows-d..anese-softkeyapplet_31bf3856ad364e35 [10.0.22621.2506] -> imjpskey.dll
wow64_microsoft-windows-d..ashared-candidateui_31bf3856ad364e35 [10.0.22621.2506] -> mscand20.dll
wow64_microsoft-windows-d..ashared-filemanager_31bf3856ad364e35 [10.0.22621.2506] -> imefiles.dll
wow64_microsoft-windows-d..ces-ime-eashared-lm_31bf3856ad364e35 [10.0.22621.2506] -> imelm.dll
wow64_microsoft-windows-d..characterlistapplet_31bf3856ad364e35 [10.0.22621.2506] -> imjpclst.dll
wow64_microsoft-windows-d..d-searchintegration_31bf3856ad364e35 [10.0.22621.2506] -> imesearch.exe, imesearchdll.dll, imesearchps.dll
wow64_microsoft-windows-d..direct3dshadercache_31bf3856ad364e35 [10.0.22621.2506] -> d3dscache.dll
wow64_microsoft-windows-d..e-coretipjpnprofile_31bf3856ad364e35 [10.0.22621.2506] -> imjptip.dll
wow64_microsoft-windows-d..e-eashared-kjshared_31bf3856ad364e35 [10.0.22621.2506] -> imjkapi.dll
wow64_microsoft-windows-d..e-handwritingapplet_31bf3856ad364e35 [10.0.22621.2506] -> imjpcac.dll
wow64_microsoft-windows-d..ecomponent-binaries_31bf3856ad364e35 [10.0.22621.2506] -> chsifecomp.dll
wow64_microsoft-windows-d..ent-dmpolicymanager_31bf3856ad364e35 [10.0.22621.2715] * -> policymanager.dll
wow64_microsoft-windows-d..es-smartcards-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.smartcards.dll
wow64_microsoft-windows-d..ime-eashared-imepad_31bf3856ad364e35 [10.0.22621.2506] -> imepadsm.dll, imepadsv.exe, padrs404.dll, padrs411.dll, padrs804.dll
wow64_microsoft-windows-d..japanese-customizer_31bf3856ad364e35 [10.0.22621.2506] -> imjpcus.dll
wow64_microsoft-windows-d..japanese-prediction_31bf3856ad364e35 [10.0.22621.2506] -> imjppred.dll
wow64_microsoft-windows-d..japanese-propertyui_31bf3856ad364e35 [10.0.22621.2506] -> imjputyc.dll
wow64_microsoft-windows-d..lekanjifinderapplet_31bf3856ad364e35 [10.0.22621.2506] -> imjpskf.dll
wow64_microsoft-windows-d..management-omadmapi_31bf3856ad364e35 [10.0.22621.2715] * -> omadmapi.dll
wow64_microsoft-windows-d..me-eashared-coretip_31bf3856ad364e35 [10.0.22621.2506] -> imetip.dll
wow64_microsoft-windows-d..me-japanese-dictapi_31bf3856ad364e35 [10.0.22621.2506] -> imjpdapi.dll
wow64_microsoft-windows-d..me-japanese-setting_31bf3856ad364e35 [10.0.22621.2506] -> imjpset.exe
wow64_microsoft-windows-d..nagement-dmcfgutils_31bf3856ad364e35 [10.0.22621.2506] -> dmcfgutils.dll
wow64_microsoft-windows-d..nagement-dmcmnutils_31bf3856ad364e35 [10.0.22621.2506] -> dmcmnutils.dll
wow64_microsoft-windows-d..ndowmanager-effects_31bf3856ad364e35 [10.0.22621.2506] -> wuceffects.dll
wow64_microsoft-windows-d..nese-eacommonapijpn_31bf3856ad364e35 [10.0.22621.2506] -> imjpapi.dll
wow64_microsoft-windows-d..njifinderdictionary_31bf3856ad364e35 [10.0.22621.2506] -> imjpkdic.dll
wow64_microsoft-windows-d..ointofservice-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.pointofservice.dll
wow64_microsoft-windows-d..omerfeedbackmanager_31bf3856ad364e35 [10.0.22621.2506] -> imecfm.dll, imecfmps.dll, imecfmui.exe
wow64_microsoft-windows-d..opwindowmanager-api_31bf3856ad364e35 [10.0.22621.2506] -> dwmapi.dll
wow64_microsoft-windows-d..oryservices-dsparse_31bf3856ad364e35 [10.0.22621.2506] -> dsparse.dll
wow64_microsoft-windows-d..oryservices-ntdsapi_31bf3856ad364e35 [10.0.22621.2506] -> ntdsapi.dll, w32topl.dll
wow64_microsoft-windows-d..pisetexthostdesktop_31bf3856ad364e35 [10.0.22621.2506] -> dmapisetextimpldesktop.dll
wow64_microsoft-windows-d..riseresourcemanager_31bf3856ad364e35 [10.0.22621.2506] -> enterpriseresourcemanager.dll
wow64_microsoft-windows-d..t-winproviders-appx_31bf3856ad364e35 [10.0.22621.2506] -> appxprovider.dll
wow64_microsoft-windows-d..t-winproviders-edge_31bf3856ad364e35 [10.0.22621.2506] -> edgeprovider.dll
wow64_microsoft-windows-d..tofservice-oposhost_31bf3856ad364e35 [10.0.22621.2506] -> oposhost.exe
wow64_microsoft-windows-d..tx-d3d11_3sdklayers_31bf3856ad364e35 [10.0.22621.2506] -> d3d11_3sdklayers.dll
wow64_microsoft-windows-d..tx-vsd3dwarp12debug_31bf3856ad364e35 [10.0.22621.2506] -> vsd3dwarpdebug.dll
wow64_microsoft-windows-d2d_31bf3856ad364e35 [10.0.22621.2506] -> d2d1.dll
wow64_microsoft-windows-data-pdf_31bf3856ad364e35 [10.0.22621.2506] -> windows.data.pdf.dll
wow64_microsoft-windows-dataclen_31bf3856ad364e35 [10.0.22621.2506] -> dataclen.dll
wow64_microsoft-windows-dataexchange-api_31bf3856ad364e35 [10.0.22621.2506] -> dataexchange.dll
wow64_microsoft-windows-ddores_31bf3856ad364e35 [10.0.22621.2506] -> ddores.dll
wow64_microsoft-windows-debughelp_31bf3856ad364e35 [10.0.22621.2506] -> dbghelp.dll
wow64_microsoft-windows-deltacompressionengine_31bf3856ad364e35 [10.0.22621.2506] -> msdelta.dll, mspatcha.dll, mspatchc.dll
wow64_microsoft-windows-deltapackageexpander_31bf3856ad364e35 [10.0.22621.2506] -> dpx.dll
wow64_microsoft-windows-desk_31bf3856ad364e35 [10.0.22621.2506] -> desk.cpl
wow64_microsoft-windows-devdispitemprovider_31bf3856ad364e35 [10.0.22621.2506] -> devdispitemprovider.dll
wow64_microsoft-windows-devicecenter_31bf3856ad364e35 [10.0.22621.2506] -> devicecenter.dll
wow64_microsoft-windows-deviceflows-datamodel_31bf3856ad364e35 [10.0.22621.2506] -> deviceflows.datamodel.dll
wow64_microsoft-windows-devicepairingdll_31bf3856ad364e35 [10.0.22621.2506] -> devicepairing.dll
wow64_microsoft-windows-devicepairingfolder_31bf3856ad364e35 [10.0.22621.2506] -> devicepairingfolder.dll
wow64_microsoft-windows-devices-background_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.background.dll, windows.devices.background.ps.dll
wow64_microsoft-windows-devices-bluetooth_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.bluetooth.dll
wow64_microsoft-windows-devices-custom_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.custom.dll, windows.devices.custom.ps.dll
wow64_microsoft-windows-devices-enumeration_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.enumeration.dll
wow64_microsoft-windows-devices-lights-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.lights.dll
wow64_microsoft-windows-devices-radios_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.radios.dll
wow64_microsoft-windows-devices-wifi_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.wifi.dll
wow64_microsoft-windows-devices-wifidirect_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.wifidirect.dll
wow64_microsoft-windows-dhcp-client-dll-minwin_31bf3856ad364e35 [10.0.22621.2506] -> dhcpcore.dll, dhcpcore6.dll, dhcpcsvc.dll, dhcpcsvc6.dll
wow64_microsoft-windows-dhcpds_31bf3856ad364e35 [10.0.22621.2506] -> dsauth.dll
wow64_microsoft-windows-dhcpserverapi_31bf3856ad364e35 [10.0.22621.2506] -> dhcpsapi.dll
wow64_microsoft-windows-dims-keyroam_31bf3856ad364e35 [10.0.22621.2506] -> adprovider.dll, capiprovider.dll, cngprovider.dll, dimsroam.dll, dpapiprovider.dll, wincredprovider.dll
wow64_microsoft-windows-directcomposition_31bf3856ad364e35 [10.0.22621.2715] * -> dcomp.dll
wow64_microsoft-windows-directmanipulation_31bf3856ad364e35 [10.0.22621.2506] -> directmanipulation.dll
wow64_microsoft-windows-directory-services-sam_31bf3856ad364e35 [10.0.22621.2506] -> offlinesam.dll, samlib.dll
wow64_microsoft-windows-directshow-core_31bf3856ad364e35 [10.0.22621.2506] -> quartz.dll
wow64_microsoft-windows-directshow-dvdsupport_31bf3856ad364e35 [10.0.22621.2506] -> qdvd.dll
wow64_microsoft-windows-directui_31bf3856ad364e35 [10.0.22621.2715] * -> windows.ui.xaml.dll
wow64_microsoft-windows-directwrite_31bf3856ad364e35 [10.0.22621.2506] -> dwrite.dll, textshaping.dll
wow64_microsoft-windows-directx-d2d1debug3_31bf3856ad364e35 [10.0.22621.2506] -> d2d1debug3.dll
wow64_microsoft-windows-directx-d3d10level9_31bf3856ad364e35 [10.0.22621.2506] -> d3d10level9.dll
wow64_microsoft-windows-directx-d3d12sdklayers_31bf3856ad364e35 [10.0.22621.2506] -> d3d12sdklayers.dll
wow64_microsoft-windows-directx-d3dcompiler_31bf3856ad364e35 [10.0.22621.2506] -> d3dcompiler_47.dll
wow64_microsoft-windows-directx-ddisplay_31bf3856ad364e35 [10.0.22621.2506] -> ddisplay.dll
wow64_microsoft-windows-directx-direct3d10.1_31bf3856ad364e35 [10.0.22621.2506] -> d3d10_1.dll, d3d10_1core.dll
wow64_microsoft-windows-directx-direct3d11_31bf3856ad364e35 [10.0.22621.2506] -> d3d11.dll
wow64_microsoft-windows-directx-direct3d11on12_31bf3856ad364e35 [10.0.22621.2506] -> d3d11on12.dll
wow64_microsoft-windows-directx-direct3d12_31bf3856ad364e35 [10.0.22621.2506] -> d3d12.dll, d3d12core.dll
wow64_microsoft-windows-directx-direct3d9_31bf3856ad364e35 [10.0.22621.2506] -> d3d8thk.dll, d3d9.dll
wow64_microsoft-windows-directx-direct3d9on12_31bf3856ad364e35 [10.0.22621.2506] -> d3d9on12.dll
wow64_microsoft-windows-directx-dxgi_31bf3856ad364e35 [10.0.22621.2506] -> dxgi.dll
wow64_microsoft-windows-directx-warp10_31bf3856ad364e35 [10.0.22621.2506] -> d3d10warp.dll
wow64_microsoft-windows-diskusage_31bf3856ad364e35 [10.0.22621.2506] -> diskusage.exe
wow64_microsoft-windows-displaymanager_31bf3856ad364e35 [10.0.22621.2506] -> displaymanager.dll
wow64_microsoft-windows-dns-client-minwin_31bf3856ad364e35 [10.0.22621.2506] -> dnsapi.dll
wow64_microsoft-windows-dns-clientsnapin_31bf3856ad364e35 [10.0.22621.2506] -> dnscmmc.dll
wow64_microsoft-windows-dolbyatmosdecmft_31bf3856ad364e35 [10.0.22621.2715] * -> dolbydecmft.dll
wow64_microsoft-windows-dot3svc_31bf3856ad364e35 [10.0.22621.2506] -> dot3api.dll, dot3msm.dll
wow64_microsoft-windows-drvstore_31bf3856ad364e35 [10.0.22621.2506] -> drvstore.dll
wow64_microsoft-windows-dui70_31bf3856ad364e35 [10.0.22621.2506] -> dui70.dll
wow64_microsoft-windows-e..-management-onecore_31bf3856ad364e35 [10.0.22621.2506] -> enterpriseappmgmtclient.dll
wow64_microsoft-windows-e..-protocol-host-peer_31bf3856ad364e35 [10.0.22621.2506] -> eapp3hst.dll, eappcfg.dll, eappgnui.dll, eapphost.dll, eappprxy.dll
wow64_microsoft-windows-e..-unifiedwritefilter_31bf3856ad364e35 [10.0.22621.2506] -> uwfwmi.dll
wow64_microsoft-windows-e..estorageengine-isam_31bf3856ad364e35 [10.0.22621.2506] -> esent.dll
wow64_microsoft-windows-e..gationconfiguration_31bf3856ad364e35 [10.0.22621.2506] -> mitigationconfiguration.dll
wow64_microsoft-windows-e..llment-winrt-client_31bf3856ad364e35 [10.0.22621.2506] -> dmalertlistener.proxystub.dll, windows.internal.management.dll
wow64_microsoft-windows-e..ortingcompatibility_31bf3856ad364e35 [10.0.22621.2506] -> dwwin.exe
wow64_microsoft-windows-eapprivateutil_31bf3856ad364e35 [10.0.22621.2506] -> eapputil.dll
wow64_microsoft-windows-eapteap_31bf3856ad364e35 [10.0.22621.2506] -> eapteapconfig.dll
wow64_microsoft-windows-eapttls_31bf3856ad364e35 [10.0.22621.2506] -> ttlsauth.dll, ttlscfg.dll
wow64_microsoft-windows-edition-transmogrifier_31bf3856ad364e35 [10.0.22621.2506] -> transmogprovider.dll
wow64_microsoft-windows-edp-notify_31bf3856ad364e35 [10.0.22621.2506] -> bitlockercsp.dll, edpnotify.exe
wow64_microsoft-windows-enhancedvideorenderer_31bf3856ad364e35 [10.0.22621.2506] -> evr.dll
wow64_microsoft-windows-enrollengine_31bf3856ad364e35 [10.0.22621.2715] * -> dmenrollengine.dll, enrollmentapi.dll
wow64_microsoft-windows-errorreportingcore_31bf3856ad364e35 [10.0.22621.2506] -> wer.dll, werdiagcontroller.dll, weretw.dll, wermgr.exe
wow64_microsoft-windows-errorreportingfaults_31bf3856ad364e35 [10.0.22621.2506] -> faultrep.dll, werenc.dll, werfault.exe, werfaultsecure.exe
wow64_microsoft-windows-esdsip_31bf3856ad364e35 [10.0.22621.2506] -> esdsip.dll
wow64_microsoft-windows-eventcollector_31bf3856ad364e35 [10.0.22621.2506] -> wecapi.dll, wecutil.exe
wow64_microsoft-windows-eventlog-api_31bf3856ad364e35 [10.0.22621.2506] -> wevtapi.dll
wow64_microsoft-windows-eventlog-commandline_31bf3856ad364e35 [10.0.22621.2506] -> wevtutil.exe
wow64_microsoft-windows-eventlog-forwardplugin_31bf3856ad364e35 [10.0.22621.2506] -> wevtfwd.dll
wow64_microsoft-windows-execmodel-client_31bf3856ad364e35 [10.0.22621.2506] -> execmodelclient.dll
wow64_microsoft-windows-explorer_31bf3856ad364e35 [10.0.22621.2715] * -> explorer.exe
wow64_microsoft-windows-explorerframe_31bf3856ad364e35 [10.0.22621.2506] -> explorerframe.dll
wow64_microsoft-windows-f..allconfig-installer_31bf3856ad364e35 [10.0.22621.2506] -> cmifw.dll
wow64_microsoft-windows-f..eatureconfiguration_31bf3856ad364e35 [10.0.22621.2506] -> fcon.dll
wow64_microsoft-windows-f..mutilityrefslibrary_31bf3856ad364e35 [10.0.22621.2506] -> urefs.dll
wow64_microsoft-windows-f..rcluster-clientcore_31bf3856ad364e35 [10.0.22621.2506] -> clusapi.dll, resutils.dll
wow64_microsoft-windows-f..temutilitylibraries_31bf3856ad364e35 [10.0.22621.2506] -> ifsutil.dll, ulib.dll
wow64_microsoft-windows-f..tilityrefsv1library_31bf3856ad364e35 [10.0.22621.2506] -> urefsv1.dll
wow64_microsoft-windows-f..utilitylibrariesext_31bf3856ad364e35 [10.0.22621.2506] -> cmdext.dll, fsutilext.dll
wow64_microsoft-windows-f..yphanimator-library_31bf3856ad364e35 [10.0.22621.2506] -> fontglyphanimator.dll
wow64_microsoft-windows-fax-common_31bf3856ad364e35 [10.0.22621.2506] -> fxsapi.dll, fxscom.dll, fxscomex.dll, fxsresm.dll, winfax.dll
wow64_microsoft-windows-fax-mapi_31bf3856ad364e35 [10.0.22621.2506] -> fxsext32.dll, fxsxp32.dll
wow64_microsoft-windows-fdeploy_31bf3856ad364e35 [10.0.22621.2506] -> fdeploy.dll, frprov.dll, ustprov.dll
wow64_microsoft-windows-feclient_31bf3856ad364e35 [10.0.22621.2506] -> feclient.dll
wow64_microsoft-windows-fileexplorer-common_31bf3856ad364e35 [10.0.22621.2506] -> windows.fileexplorer.common.dll
wow64_microsoft-windows-flighting-settings_31bf3856ad364e35 [10.0.22621.2506] -> flightsettings.dll
wow64_microsoft-windows-fmifs_31bf3856ad364e35 [10.0.22621.2506] -> fmifs.dll
wow64_microsoft-windows-fontext_31bf3856ad364e35 [10.0.22621.2506] -> fontext.dll
wow64_microsoft-windows-frameworkudk_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.internal.frameworkudk.system.dll
wow64_microsoft-windows-fsutil_31bf3856ad364e35 [10.0.22621.2506] -> fsutil.exe
wow64_microsoft-windows-ftp_31bf3856ad364e35 [10.0.22621.2506] -> ftp.exe
wow64_microsoft-windows-g..-brightnessoverride_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.display.brightnessoverride.dll
wow64_microsoft-windows-g..enhancementoverride_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.display.displayenhancementoverride.dll
wow64_microsoft-windows-g..policy-admin-gpedit_31bf3856ad364e35 [10.0.22621.2506] -> gpedit.dll
wow64_microsoft-windows-g..ppolicy-policymaker_31bf3856ad364e35 [10.0.22621.2506] -> gpprefcl.dll
wow64_microsoft-windows-gdi-painting_31bf3856ad364e35 [10.0.22621.2506] -> mf3216.dll, msimg32.dll
wow64_microsoft-windows-gdi32_31bf3856ad364e35 [10.0.22621.2506] -> gdi32.dll
wow64_microsoft-windows-gdi32full_31bf3856ad364e35 [10.0.22621.2506] -> gdi32full.dll
wow64_microsoft-windows-gdi_31bf3856ad364e35 [10.0.22621.2506] -> atmlib.dll, dciman32.dll, fontsub.dll, lpk.dll
wow64_microsoft-windows-geolocation-framework_31bf3856ad364e35 [10.0.22621.2506] -> locationframeworkinternalps.dll, locationframeworkps.dll
wow64_microsoft-windows-geolocation-winrt_31bf3856ad364e35 [10.0.22621.2506] -> geolocation.dll
wow64_microsoft-windows-globalization_31bf3856ad364e35 [10.0.22621.2506] -> windows.globalization.dll
wow64_microsoft-windows-graphics-dispbroker_31bf3856ad364e35 [10.0.22621.2506] -> dispbroker.dll
wow64_microsoft-windows-graphicscapture_31bf3856ad364e35 [10.0.22621.2506] -> graphicscapture.dll
wow64_microsoft-windows-grouppolicy-base_31bf3856ad364e35 [10.0.22621.2506] -> gpapi.dll
wow64_microsoft-windows-h..applicationguardcsp_31bf3856ad364e35 [10.0.22621.2506] -> windowsdefenderapplicationguardcsp.dll
wow64_microsoft-windows-h..public-utils-shared_31bf3856ad364e35 [10.0.22621.2506] -> hvsiproxyapp.exe, isolatedwindowsenvironmentutils.dll
wow64_microsoft-windows-heatcore_31bf3856ad364e35 [10.0.22621.2506] -> heatcore.dll, windowsdefaultheatprocessor.dll
wow64_microsoft-windows-hlink_31bf3856ad364e35 [10.0.22621.2506] -> hlink.dll
wow64_microsoft-windows-hnetcfgclient_31bf3856ad364e35 [10.0.22621.2506] -> hnetcfgclient.dll
wow64_microsoft-windows-holoshellruntime_31bf3856ad364e35 [10.0.22621.2506] -> holoshellruntime.dll
wow64_microsoft-windows-http-api_31bf3856ad364e35 [10.0.22621.2506] -> httpapi.dll
wow64_microsoft-windows-hvsi-management-api_31bf3856ad364e35 [10.0.22621.2506] -> hvsimanagementapi.dll
wow64_microsoft-windows-hvsi-manager_31bf3856ad364e35 [10.0.22621.2506] -> hvsifiletrust.dll, hvsimgrps.dll
wow64_microsoft-windows-hvsi-service_31bf3856ad364e35 [10.0.22621.2506] -> hvsicontainerservice.dll
wow64_microsoft-windows-i..-accountscontrolexp_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.shellcommon.accountscontrolexperience.dll
wow64_microsoft-windows-i..-japanese_nec_win95_31bf3856ad364e35 [10.0.22621.2506] -> kbdnec95.dll
wow64_microsoft-windows-i..-unicode-components_31bf3856ad364e35 [10.0.22621.2506] -> icu.dll, icuin.dll, icuuc.dll
wow64_microsoft-windows-i..2-filesystemsupport_31bf3856ad364e35 [10.0.22621.2506] -> imapi2fs.dll
wow64_microsoft-windows-i..ard-japanese_nec-at_31bf3856ad364e35 [10.0.22621.2506] -> kbdnecat.dll
wow64_microsoft-windows-i..cachingbasebinaries_31bf3856ad364e35 [10.0.22621.2506] -> cachfile.dll, cachtokn.dll, cachuri.dll
wow64_microsoft-windows-i..chinese-tip_profile_31bf3856ad364e35 [10.0.22621.2506] -> imtctip.dll
wow64_microsoft-windows-i..d-japanese_nec98-nt_31bf3856ad364e35 [10.0.22621.2506] -> kbdnecnt.dll
wow64_microsoft-windows-i..ectionsharingconfig_31bf3856ad364e35 [10.0.22621.2506] -> hnetcfg.dll
wow64_microsoft-windows-i..ersandsecurityzones_31bf3856ad364e35 [11.0.22621.2506] -> urlmon.dll
wow64_microsoft-windows-i..eyboard-korean_101a_31bf3856ad364e35 [10.0.22621.2506] -> kbd101a.dll
wow64_microsoft-windows-i..eyboard-korean_101b_31bf3856ad364e35 [10.0.22621.2506] -> kbd101b.dll
wow64_microsoft-windows-i..eyboard-korean_101c_31bf3856ad364e35 [10.0.22621.2506] -> kbd101c.dll
wow64_microsoft-windows-i..hancementmanagement_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.graphics.display.displayenhancementmanagement.dll
wow64_microsoft-windows-i..henticationbinaries_31bf3856ad364e35 [10.0.22621.2506] -> authmap.dll
wow64_microsoft-windows-i..hinese-imepadapplet_31bf3856ad364e35 [10.0.22621.2506] -> imtccac.dll, imtcdic.dll, imtcskf.dll
wow64_microsoft-windows-i..i_initiator_service_31bf3856ad364e35 [10.0.22621.2506] -> iscsicli.exe, iscsidsc.dll, iscsied.dll, iscsium.dll, iscsiwmi.dll, iscsiwmiv2.dll
wow64_microsoft-windows-i..iextensionsbinaries_31bf3856ad364e35 [10.0.22621.2506] -> isapi.dll
wow64_microsoft-windows-i..keyboard-korean_103_31bf3856ad364e35 [10.0.22621.2506] -> kbd103.dll
wow64_microsoft-windows-i..l-devices-bluetooth_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.devices.bluetooth.dll
wow64_microsoft-windows-i..l-keyboard-00000c1a_31bf3856ad364e35 [10.0.22621.2506] -> kbdycc.dll
wow64_microsoft-windows-i..l-keyboard-0000201a_31bf3856ad364e35 [10.0.22621.2506] -> kbdbhc.dll
wow64_microsoft-windows-i..l-keyboard-0001045c_31bf3856ad364e35 [10.0.22621.2506] -> kbdcherp.dll
wow64_microsoft-windows-i..ldhangul-tipprofile_31bf3856ad364e35 [10.0.22621.2506] -> imkrotip.dll
wow64_microsoft-windows-i..lineid-wamextension_31bf3856ad364e35 [10.0.22621.2506] -> microsoftaccountwamextension.dll
wow64_microsoft-windows-i..nal-core-locale-nls_31bf3856ad364e35 [10.0.22621.2506] -> winnlsres.dll
wow64_microsoft-windows-i..nese-core-essential_31bf3856ad364e35 [10.0.22621.2506] -> imtccfg.dll, imtccore.dll
wow64_microsoft-windows-i..nternetcontrolpanel_31bf3856ad364e35 [11.0.22621.2506] -> inetcpl.cpl
wow64_microsoft-windows-i..oard-japanese_ibm02_31bf3856ad364e35 [10.0.22621.2506] -> kbdibm02.dll
wow64_microsoft-windows-i..on-aad-wamextension_31bf3856ad364e35 [10.0.22621.2506] -> aadwamextension.dll
wow64_microsoft-windows-i..panese_ax2_keyboard_31bf3856ad364e35 [10.0.22621.2506] -> kbdax2.dll
wow64_microsoft-windows-i..panese_dec_lk411-aj_31bf3856ad364e35 [10.0.22621.2506] -> kbdlk41a.dll
wow64_microsoft-windows-i..playcolormanagement_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.graphics.display.displaycolormanagement.dll
wow64_microsoft-windows-i..raries-servercommon_31bf3856ad364e35 [10.0.22621.2506] -> ahadmin.dll, appcmd.exe, appobj.dll, cngkeyhelper.dll, iisres.dll, iisrtl.dll, iissetup.exe, iissyspr.dll, iisutil.dll, nativerd.dll, rsca.dll, rscaext.dll, w3ctrlps.dll
wow64_microsoft-windows-i..rd-japanese_106_key_31bf3856ad364e35 [10.0.22621.2506] -> kbd106.dll, kbd106n.dll
wow64_microsoft-windows-i..rewebenginebinaries_31bf3856ad364e35 [10.0.22621.2506] -> hwebcore.dll, iiscore.dll, w3dt.dll
wow64_microsoft-windows-i..rnational-timezones_31bf3856ad364e35 [10.0.22621.2506] -> tzres.dll
wow64_microsoft-windows-i..se_standard_101_key_31bf3856ad364e35 [10.0.22621.2506] -> kbd101.dll
wow64_microsoft-windows-i..switch-toasthandler_31bf3856ad364e35 [10.0.22621.2506] -> inputswitchtoasthandler.exe
wow64_microsoft-windows-i..tional-chinese-core_31bf3856ad364e35 [10.0.22621.2506] -> imtclnwz.exe, imtcprop.exe, imtctrln.dll
wow64_microsoft-windows-i..tmlrendering-legacy_31bf3856ad364e35 [11.0.22621.2506] -> indexeddblegacy.dll, mshtml.dll
wow64_microsoft-windows-i..tocolimplementation_31bf3856ad364e35 [11.0.22621.2506] -> jsproxy.dll, wininet.dll
wow64_microsoft-windows-icm-base_31bf3856ad364e35 [10.0.22621.2506] -> icm32.dll, mscms.dll
wow64_microsoft-windows-idctrls_31bf3856ad364e35 [10.0.22621.2506] -> idctrls.dll
wow64_microsoft-windows-ie-antiphishfilter_31bf3856ad364e35 [11.0.22621.2506] -> ieapfltr.dll
wow64_microsoft-windows-ie-behaviors_31bf3856ad364e35 [11.0.22621.2506] -> iepeers.dll
wow64_microsoft-windows-ie-directxtransforms_31bf3856ad364e35 [11.0.22621.2506] -> dxtmsft.dll, dxtrans.dll
wow64_microsoft-windows-ie-htmlapplication_31bf3856ad364e35 [11.0.22621.2506] -> mshta.exe
wow64_microsoft-windows-ie-htmlrendering_31bf3856ad364e35 [11.0.22621.2715] * -> edgehtml.dll, edgemanager.dll, webplatstorageserver.dll
wow64_microsoft-windows-ie-runtimeutilities_31bf3856ad364e35 [11.0.22621.2506] -> edgeiso.dll, iertutil.dll, msiso.dll
wow64_microsoft-windows-ie-setup-support_31bf3856ad364e35 [11.0.22621.2506] -> iernonce.dll, iesetup.dll
wow64_microsoft-windows-ieframe_31bf3856ad364e35 [11.0.22621.2715] * -> ieframe.dll, iemigplugin.dll
wow64_microsoft-windows-iis-httpcachebinaries_31bf3856ad364e35 [10.0.22621.2506] -> cachhttp.dll
wow64_microsoft-windows-imageres_31bf3856ad364e35 [10.0.22621.2506] -> imageres.dll
wow64_microsoft-windows-imapiv2-legacyshim_31bf3856ad364e35 [10.0.22621.2506] -> imapi.dll
wow64_microsoft-windows-ime-eashared-ccshared_31bf3856ad364e35 [10.0.22621.2506] -> imccphr.exe, imedicapiccps.dll
wow64_microsoft-windows-ime-korean-cacpad_31bf3856ad364e35 [10.0.22621.2506] -> imkrcac.dll
wow64_microsoft-windows-ime-korean-commonapi_31bf3856ad364e35 [10.0.22621.2506] -> imkrapi.dll
wow64_microsoft-windows-ime-korean-hanjadic_31bf3856ad364e35 [10.0.22621.2506] -> imkrhjd.dll
wow64_microsoft-windows-ime-korean-padresource_31bf3856ad364e35 [10.0.22621.2506] -> padrs412.dll
wow64_microsoft-windows-ime-korean-skfpad_31bf3856ad364e35 [10.0.22621.2506] -> imkrskf.dll
wow64_microsoft-windows-ime-korean-tipprofile_31bf3856ad364e35 [10.0.22621.2506] -> imkrtip.dll
wow64_microsoft-windows-ime-korean-tools_31bf3856ad364e35 [10.0.22621.2506] -> imkrudt.dll
wow64_microsoft-windows-imm32_31bf3856ad364e35 [10.0.22621.2506] -> imm32.dll
wow64_microsoft-windows-inputservice_31bf3856ad364e35 [10.0.22621.2506] -> editbuffertesthook.dll, textinputmethodformatter.dll, windows.ui.core.textinput.dll, wordbreakers.dll
wow64_microsoft-windows-inputswitch_31bf3856ad364e35 [10.0.22621.2506] -> inputswitch.dll
wow64_microsoft-windows-installer-engine_31bf3856ad364e35 [10.0.22621.2506] -> msi.dll, msimsg.dll
wow64_microsoft-windows-installer-sip_31bf3856ad364e35 [10.0.22621.2506] -> msisip.dll
wow64_microsoft-windows-internal-ui-dialogs_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.ui.dialogs.dll
wow64_microsoft-windows-international-nlsbuild_31bf3856ad364e35 [10.0.22621.2506] -> nlsbres.dll
wow64_microsoft-windows-international-unattend_31bf3856ad364e35 [10.0.22621.2506] -> muiunattend.exe
wow64_microsoft-windows-intl_31bf3856ad364e35 [10.0.22621.2506] -> intl.cpl
wow64_microsoft-windows-ipconfig_31bf3856ad364e35 [10.0.22621.2506] -> ipconfig.exe
wow64_microsoft-windows-kernel-appcore_31bf3856ad364e35 [10.0.22621.2715] * -> kernel.appcore.dll
wow64_microsoft-windows-kernel32_31bf3856ad364e35 [10.0.22621.2506] -> kernel32.dll
wow64_microsoft-windows-kernelbase_31bf3856ad364e35 [10.0.22621.2715] * -> kernelbase.dll
wow64_microsoft-windows-keymgr_31bf3856ad364e35 [10.0.22621.2506] -> keymgr.dll
wow64_microsoft-windows-l..st-abovelockapphost_31bf3856ad364e35 [10.0.22621.2506] -> abovelockapphost.dll
wow64_microsoft-windows-languagesdb-onecore_31bf3856ad364e35 [10.0.22621.2506] -> globinputhost.dll, userlanguageprofilecallback.dll, winlangdb.dll
wow64_microsoft-windows-ldap-client_31bf3856ad364e35 [10.0.22621.2506] -> wldap32.dll
wow64_microsoft-windows-lockappbroker-winrt_31bf3856ad364e35 [10.0.22621.2506] -> lockappbroker.dll
wow64_microsoft-windows-lockscreendata_31bf3856ad364e35 [10.0.22621.2506] -> lockscreendata.dll
wow64_microsoft-windows-lsa-minwin_31bf3856ad364e35 [10.0.22621.2506] -> sspicli.dll
wow64_microsoft-windows-lsa_31bf3856ad364e35 [10.0.22621.2506] -> offlinelsa.dll
wow64_microsoft-windows-lxss-manager_31bf3856ad364e35 [10.0.22621.2506] -> lxssmanagerproxystub.dll
wow64_microsoft-windows-m..-activesyncprovider_31bf3856ad364e35 [10.0.22621.2506] -> activesyncprovider.dll
wow64_microsoft-windows-m..-management-console_31bf3856ad364e35 [10.0.22621.2506] -> cic.dll, mmc.exe, mmcbase.dll, mmcshext.dll
wow64_microsoft-windows-m..ation-mfmediaengine_31bf3856ad364e35 [10.0.22621.2506] -> mfmediaengine.dll
wow64_microsoft-windows-m..ation-mfphotography_31bf3856ad364e35 [10.0.22621.2506] -> msphotography.dll
wow64_microsoft-windows-m..band-experience-api_31bf3856ad364e35 [10.0.22621.2506] -> mbaeapipublic.dll
wow64_microsoft-windows-m..c-drivermanager-dll_31bf3856ad364e35 [10.0.22621.2506] -> odbc32.dll
wow64_microsoft-windows-m..d-experience-smsapi_31bf3856ad364e35 [10.0.22621.2506] -> mbsmsapi.dll
wow64_microsoft-windows-m..ents-mdac-oledb-dll_31bf3856ad364e35 [10.0.22621.2506] -> oledb32.dll
wow64_microsoft-windows-m..n-frameserverclient_31bf3856ad364e35 [10.0.22621.2506] -> frameserverclient.dll, mfsensorgroup.dll
wow64_microsoft-windows-m..nents-mdac-msdadiag_31bf3856ad364e35 [10.0.22621.2506] -> msdadiag.dll
wow64_microsoft-windows-m..qlserver-driver-dll_31bf3856ad364e35 [10.0.22621.2506] -> sqlsrv32.dll
wow64_microsoft-windows-m..rience-api-internal_31bf3856ad364e35 [10.0.22621.2506] -> mbaeapi.dll
wow64_microsoft-windows-m..server-provider-dll_31bf3856ad364e35 [10.0.22621.2715] * -> sqloledb.dll
wow64_microsoft-windows-m..servermonitorclient_31bf3856ad364e35 [10.0.22621.2506] -> frameservermonitorclient.dll
wow64_microsoft-windows-magnify_31bf3856ad364e35 [10.0.22621.2506] -> magnify.exe
wow64_microsoft-windows-mapcontrol_31bf3856ad364e35 [10.0.22621.2506] -> bingmaps.dll, bingonlineservices.dll, jpmapcontrol.dll, mapconfiguration.dll, mapcontrolcore.dll, mapcontrolstringsres.dll, mapgeocoder.dll, maprouter.dll, mapsbtsvc.dll, moshostclient.dll, mosstorage.dll, nmadirect.dll, ztrace_maps.dll
wow64_microsoft-windows-mapi-mmga_31bf3856ad364e35 [10.0.22621.2506] -> mmgaclient.dll, mmgaproxystub.dll, mmgaserver.exe
wow64_microsoft-windows-mapi_31bf3856ad364e35 [10.0.22621.2506] -> fixmapi.exe, mapi32.dll, mapistub.dll
wow64_microsoft-windows-mccs-synccontroller_31bf3856ad364e35 [10.0.22621.2506] -> synccontroller.dll
wow64_microsoft-windows-mcrecvsrc_31bf3856ad364e35 [10.0.22621.2506] -> mcrecvsrc.dll
wow64_microsoft-windows-mdmregistration2_31bf3856ad364e35 [10.0.22621.2506] -> mdmregistration.dll
wow64_microsoft-windows-media-audio_31bf3856ad364e35 [10.0.22621.2715] * -> windows.media.audio.dll
wow64_microsoft-windows-media-devices_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.devices.dll
wow64_microsoft-windows-media-import-api_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.import.dll
wow64_microsoft-windows-media-streaming-dll_31bf3856ad364e35 [10.0.22621.2715] * -> windows.media.streaming.dll
wow64_microsoft-windows-mediafoundation-mfsvr_31bf3856ad364e35 [10.0.22621.2506] -> mfsvr.dll
wow64_microsoft-windows-mediafoundation_31bf3856ad364e35 [10.0.22621.2506] -> mf.dll, mfpmp.exe
wow64_microsoft-windows-mediaplayer-core_31bf3856ad364e35 [10.0.22621.2506] -> dxmasf.dll, gnsdk_fp.dll, msdxm.ocx, spwmp.dll, wmp.dll, wmpconfig.exe, wmplayer.exe, wmploc.dll, wmpshare.exe
wow64_microsoft-windows-mediaplayer-wmpeffects_31bf3856ad364e35 [10.0.22621.2506] -> wmpeffects.dll
wow64_microsoft-windows-mfasfsrcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfasfsrcsnk.dll
wow64_microsoft-windows-mfaudiocnv_31bf3856ad364e35 [10.0.22621.2506] -> mfaudiocnv.dll
wow64_microsoft-windows-mfcore_31bf3856ad364e35 [10.0.22621.2506] -> mfcore.dll, mfps.dll
wow64_microsoft-windows-mfds_31bf3856ad364e35 [10.0.22621.2506] -> mfds.dll
wow64_microsoft-windows-mfmkvsrcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfmkvsrcsnk.dll
wow64_microsoft-windows-mfmp4srcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfmp4srcsnk.dll
wow64_microsoft-windows-mfmpeg2srcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfmpeg2srcsnk.dll
wow64_microsoft-windows-mfnetsrc_31bf3856ad364e35 [10.0.22621.2506] -> mfnetsrc.dll
wow64_microsoft-windows-mfplat_31bf3856ad364e35 [10.0.22621.2506] -> mfplat.dll
wow64_microsoft-windows-mfplay_31bf3856ad364e35 [10.0.22621.2506] -> mfplay.dll
wow64_microsoft-windows-mfreadwrite_31bf3856ad364e35 [10.0.22621.2506] -> mfreadwrite.dll
wow64_microsoft-windows-mfsrcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfsrcsnk.dll
wow64_microsoft-windows-miracast-receiver-api_31bf3856ad364e35 [10.0.22621.2506] -> miracastreceiver.dll
wow64_microsoft-windows-miracast-receiver-ext_31bf3856ad364e35 [10.0.22621.2506] -> miracastreceiverext.dll
wow64_microsoft-windows-mirage_31bf3856ad364e35 [10.0.22621.2506] -> windows.mirage.dll, windows.mirage.internal.dll
wow64_microsoft-windows-mmcss_31bf3856ad364e35 [10.0.22621.2506] -> avrt.dll
wow64_microsoft-windows-mmdeviceapi_31bf3856ad364e35 [10.0.22621.2506] -> mmdevapi.dll
wow64_microsoft-windows-mmsys_31bf3856ad364e35 [10.0.22621.2506] -> mmsys.cpl
wow64_microsoft-windows-mobilepc-location-api_31bf3856ad364e35 [10.0.22621.2506] -> locationapi.dll
wow64_microsoft-windows-mobilepc-sensors-api_31bf3856ad364e35 [10.0.22621.2506] -> sensorsapi.dll
wow64_microsoft-windows-mobsync_31bf3856ad364e35 [10.0.22621.2506] -> synccenter.dll
wow64_microsoft-windows-mp3dmod_31bf3856ad364e35 [10.0.22621.2506] -> mp3dmod.dll
wow64_microsoft-windows-msaatext_31bf3856ad364e35 [10.0.22621.2506] -> msaatext.dll
wow64_microsoft-windows-msasn1_31bf3856ad364e35 [10.0.22621.2506] -> msasn1.dll
wow64_microsoft-windows-msauddecmft_31bf3856ad364e35 [10.0.22621.2506] -> msauddecmft.dll
wow64_microsoft-windows-msauditevtlog_31bf3856ad364e35 [10.0.22621.2506] -> adtschema.dll, msaudite.dll, msobjs.dll
wow64_microsoft-windows-msdt_31bf3856ad364e35 [10.0.22621.2506] -> msdt.exe
wow64_microsoft-windows-msftedit_31bf3856ad364e35 [10.0.22621.2506] -> msftedit.dll
wow64_microsoft-windows-msieftp_31bf3856ad364e35 [10.0.22621.2506] -> msieftp.dll
wow64_microsoft-windows-msinfo32-exe-common_31bf3856ad364e35 [10.0.22621.2506] -> msinfo32.exe
wow64_microsoft-windows-msinfo32-exe_31bf3856ad364e35 [10.0.22621.2506] -> msinfo32.exe
wow64_microsoft-windows-mskeyprotcli-dll_31bf3856ad364e35 [10.0.22621.2506] -> mskeyprotcli.dll
wow64_microsoft-windows-mskeyprotect-dll_31bf3856ad364e35 [10.0.22621.2506] -> mskeyprotect.dll
wow64_microsoft-windows-msmpeg2adec_31bf3856ad364e35 [10.0.22621.2506] -> msmpeg2adec.dll
wow64_microsoft-windows-msmpeg2vdec_31bf3856ad364e35 [10.0.22621.2506] -> msmpeg2vdec.dll
wow64_microsoft-windows-mssign32-dll_31bf3856ad364e35 [10.0.22621.2506] -> mssign32.dll
wow64_microsoft-windows-msvcrt_31bf3856ad364e35 [10.0.22621.2506] -> msvcrt.dll
wow64_microsoft-windows-msvideodsp_31bf3856ad364e35 [10.0.22621.2506] -> msvideodsp.dll
wow64_microsoft-windows-msxml30_31bf3856ad364e35 [10.0.22621.2506] -> msxml3.dll, msxml3r.dll
wow64_microsoft-windows-msxml60_31bf3856ad364e35 [10.0.22621.2506] -> msxml6.dll, msxml6r.dll
wow64_microsoft-windows-mtf_31bf3856ad364e35 [10.0.22621.2506] -> mtf.dll
wow64_microsoft-windows-n.._service_runtimeapi_31bf3856ad364e35 [10.0.22621.2506] -> iashlpr.dll
wow64_microsoft-windows-n..agerdesktopprovider_31bf3856ad364e35 [10.0.22621.2506] -> npsmdesktopprovider.dll
wow64_microsoft-windows-n..ayingsessionmanager_31bf3856ad364e35 [10.0.22621.2506] -> npsm.dll
wow64_microsoft-windows-n..ion_service_iassvcs_31bf3856ad364e35 [10.0.22621.2506] -> iassvcs.dll
wow64_microsoft-windows-n..ion_service_runtime_31bf3856ad364e35 [10.0.22621.2506] -> ias.dll, iasacct.dll, iaspolcy.dll, iasrad.dll
wow64_microsoft-windows-n..n_service_datastore_31bf3856ad364e35 [10.0.22621.2506] -> iasads.dll, iasdatastore.dll, iasrecst.dll, sdohlp.dll
wow64_microsoft-windows-n..ork-setup-servicing_31bf3856ad364e35 [10.0.22621.2506] -> netdriverinstall.dll, netsetupapi.dll, netsetupengine.dll
wow64_microsoft-windows-n..orking-connectivity_31bf3856ad364e35 [10.0.22621.2506] -> ondemandconnroutehelper.dll, windows.networking.connectivity.dll
wow64_microsoft-windows-n..setup-compatibility_31bf3856ad364e35 [10.0.22621.2506] -> netcfgnotifyobjecthost.exe, netsetupshim.dll
wow64_microsoft-windows-n..sion-netprovisionsp_31bf3856ad364e35 [10.0.22621.2506] -> netprovisionsp.dll
wow64_microsoft-windows-n..tion_service_iassam_31bf3856ad364e35 [10.0.22621.2506] -> iassam.dll
wow64_microsoft-windows-n..tion_service_iassdo_31bf3856ad364e35 [10.0.22621.2506] -> iassdo.dll
wow64_microsoft-windows-n..tion_service_rassfm_31bf3856ad364e35 [10.0.22621.2506] -> rassfm.dll
wow64_microsoft-windows-naturallanguage6-base_31bf3856ad364e35 [10.0.22621.2506] -> naturallanguage6.dll
wow64_microsoft-windows-ncrypt-dll_31bf3856ad364e35 [10.0.22621.2506] -> ncrypt.dll
wow64_microsoft-windows-ncryptprov-dll_31bf3856ad364e35 [10.0.22621.2506] -> ncryptprov.dll
wow64_microsoft-windows-ncryptsslp-dll_31bf3856ad364e35 [10.0.22621.2506] -> ncryptsslp.dll
wow64_microsoft-windows-net1-command-line-tool_31bf3856ad364e35 [10.0.22621.2506] -> net1.exe
wow64_microsoft-windows-netapi32_31bf3856ad364e35 [10.0.22621.2506] -> netapi32.dll
wow64_microsoft-windows-netcoinstaller_31bf3856ad364e35 [10.0.22621.2506] -> nci.dll
wow64_microsoft-windows-netcorehelperclasses_31bf3856ad364e35 [10.0.22621.2506] -> netcorehc.dll
wow64_microsoft-windows-netjoin_31bf3856ad364e35 [10.0.22621.2506] -> netjoin.dll
wow64_microsoft-windows-netplwiz_31bf3856ad364e35 [10.0.22621.2506] -> netplwiz.dll
wow64_microsoft-windows-netshell_31bf3856ad364e35 [10.0.22621.2506] -> ncpa.cpl, netshell.dll
wow64_microsoft-windows-netutils_31bf3856ad364e35 [10.0.22621.2506] -> netutils.dll
wow64_microsoft-windows-network-qos-pacer_31bf3856ad364e35 [10.0.22621.2506] -> wshqos.dll
wow64_microsoft-windows-network-security_31bf3856ad364e35 [10.0.22621.2506] -> fwpuclnt.dll
wow64_microsoft-windows-networkbridgenetsh_31bf3856ad364e35 [10.0.22621.2506] -> hnetmon.dll
wow64_microsoft-windows-networkprofile_31bf3856ad364e35 [10.0.22621.2506] -> nlaapi.dll, nlmproxy.dll, nlmsprep.dll
wow64_microsoft-windows-newdev_31bf3856ad364e35 [10.0.22621.2506] -> ndadmin.exe, newdev.dll, newdev.exe
wow64_microsoft-windows-nlasvc-installers_31bf3856ad364e35 [10.0.22621.2506] -> nlansp_c.dll
wow64_microsoft-windows-notepad_31bf3856ad364e35 [10.0.22621.2506] -> notepad.exe
wow64_microsoft-windows-ntdll_31bf3856ad364e35 [10.0.22621.2506] -> ntdll.dll
wow64_microsoft-windows-ntlanman_31bf3856ad364e35 [10.0.22621.2506] -> ntlanman.dll
wow64_microsoft-windows-ntshrui_31bf3856ad364e35 [10.0.22621.2506] -> ntshrui.dll
wow64_microsoft-windows-o..euapcommonproxystub_31bf3856ad364e35 [10.0.22621.2506] -> onecoreuapcommonproxystub.dll
wow64_microsoft-windows-o..re-security-webauth_31bf3856ad364e35 [10.0.22621.2506] -> authbroker.dll
wow64_microsoft-windows-o..ssociationframework_31bf3856ad364e35 [10.0.22621.2506] -> deviceassociation.dll
wow64_microsoft-windows-object-picker_31bf3856ad364e35 [10.0.22621.2506] -> objsel.dll
wow64_microsoft-windows-ocsetupapi_31bf3856ad364e35 [10.0.22621.2506] -> ocsetapi.dll
wow64_microsoft-windows-offlineregistry_31bf3856ad364e35 [10.0.22621.2506] -> offreg.dll
wow64_microsoft-windows-ole-automation-legacy_31bf3856ad364e35 [10.0.22621.2506] -> olepro32.dll
wow64_microsoft-windows-ole-automation_31bf3856ad364e35 [10.0.22621.2506] -> oleaut32.dll
wow64_microsoft-windows-onecore-bluetooth-hfp_31bf3856ad364e35 [10.0.22621.2506] -> btagservice.dll
wow64_microsoft-windows-onecore-inputhost_31bf3856ad364e35 [10.0.22621.2506] -> inputhost.dll
wow64_microsoft-windows-onecore-ras-base-vpn_31bf3856ad364e35 [10.0.22621.2506] -> prxyqry.dll, rasapi32.dll
wow64_microsoft-windows-onecore-winrt-storage_31bf3856ad364e35 [10.0.22621.2715] * -> windows.storage.dll
wow64_microsoft-windows-onecorecommonproxystub_31bf3856ad364e35 [10.0.22621.2506] -> onecorecommonproxystub.dll
wow64_microsoft-windows-onecoreuap-raschap_31bf3856ad364e35 [10.0.22621.2506] -> eapprovp.dll, raschap.dll
wow64_microsoft-windows-onecoreuap-rastls_31bf3856ad364e35 [10.0.22621.2715] * -> rastls.dll
wow64_microsoft-windows-onecoreuap-wlansvc_31bf3856ad364e35 [10.0.22621.2506] -> wfdprov.dll, wlanapi.dll, wlanhlp.dll
wow64_microsoft-windows-onesettings-client_31bf3856ad364e35 [10.0.22621.2506] -> onesettingsclient.dll
wow64_microsoft-windows-opencl_31bf3856ad364e35 [10.0.22621.2506] -> opencl.dll
wow64_microsoft-windows-opengl_31bf3856ad364e35 [10.0.22621.2506] -> glu32.dll, opengl32.dll
wow64_microsoft-windows-openwith_31bf3856ad364e35 [10.0.22621.2506] -> openwith.exe
wow64_microsoft-windows-p..documenttargetprint_31bf3856ad364e35 [10.0.22621.2506] -> xpsdocumenttargetprint.dll
wow64_microsoft-windows-p..installerandprintui_31bf3856ad364e35 [10.0.22621.2506] -> compstui.dll, findnetprinters.dll, printui.exe, puiapi.dll, puiobj.dll
wow64_microsoft-windows-p..lcontrols-webfilter_31bf3856ad364e35 [10.0.22621.2506] -> wpcwebfilter.dll
wow64_microsoft-windows-p..nfiguration-cmdline_31bf3856ad364e35 [10.0.22621.2506] -> powercfg.exe
wow64_microsoft-windows-p..nsimulation-service_31bf3856ad364e35 [10.0.22621.2506] -> perceptionsimulation.proxystubs.dll, sixdofcontrollermanager.proxystubs.dll, virtualdisplaymanager.proxystubs.dll
wow64_microsoft-windows-p..otifications-client_31bf3856ad364e35 [10.0.22621.2506] -> wpnclient.dll
wow64_microsoft-windows-p..package-managed-api_31bf3856ad364e35 [10.0.22621.2506] -> provpackageapi.dll
wow64_microsoft-windows-p..randprintui-asyncui_31bf3856ad364e35 [10.0.22621.2506] -> prnntfy.dll
wow64_microsoft-windows-p..randprintui-ntprint_31bf3856ad364e35 [10.0.22621.2506] -> ntprint.dll, ntprint.exe
wow64_microsoft-windows-p..randprintui-printui_31bf3856ad364e35 [10.0.22621.2506] -> printui.dll
wow64_microsoft-windows-p..randprintui-prnfldr_31bf3856ad364e35 [10.0.22621.2506] -> prnfldr.dll
wow64_microsoft-windows-p..s-developer-library_31bf3856ad364e35 [10.0.22621.2506] -> wpnapps.dll
wow64_microsoft-windows-p..soundservice-client_31bf3856ad364e35 [10.0.22621.2506] -> playsndsrv.dll
wow64_microsoft-windows-p..talcontrolssettings_31bf3856ad364e35 [10.0.22621.2506] -> wpc.dll
wow64_microsoft-windows-p..ting-spooler-client_31bf3856ad364e35 [10.0.22621.2506] -> winspool.drv
wow64_microsoft-windows-p..unterinfrastructure_31bf3856ad364e35 [10.0.22621.2715] * -> cntrtextmig.dll
wow64_microsoft-windows-p9np_31bf3856ad364e35 [10.0.22621.2506] -> p9np.dll
wow64_microsoft-windows-packagemanager_31bf3856ad364e35 [10.0.22621.2506] -> pkgmgr.exe, ssshim.dll
wow64_microsoft-windows-pcshellcommonproxystub_31bf3856ad364e35 [10.0.22621.2506] -> pcshellcommonproxystub.dll
wow64_microsoft-windows-peertopeerdrt_31bf3856ad364e35 [10.0.22621.2506] -> drt.dll, drtprov.dll, drttransport.dll
wow64_microsoft-windows-perceptionapi-stub_31bf3856ad364e35 [10.0.22621.2506] -> windows.perception.stub.dll
wow64_microsoft-windows-perceptiondevice-dll_31bf3856ad364e35 [10.0.22621.2506] -> perceptiondevice.dll
wow64_microsoft-windows-photometadatahandler_31bf3856ad364e35 [10.0.22621.2506] -> photometadatahandler.dll
wow64_microsoft-windows-pickerhost_31bf3856ad364e35 [10.0.22621.2506] -> pickerhost.exe
wow64_microsoft-windows-ping-utilities_31bf3856ad364e35 [10.0.22621.2506] -> pathping.exe, ping.exe, tracert.exe
wow64_microsoft-windows-playtomanager_31bf3856ad364e35 [10.0.22621.2506] -> playtomanager.dll
wow64_microsoft-windows-pnpdevicemanager_31bf3856ad364e35 [10.0.22621.2506] -> devmgr.dll, dmocx.dll
wow64_microsoft-windows-powercfg_31bf3856ad364e35 [10.0.22621.2506] -> powercfg.cpl
wow64_microsoft-windows-powershell-exe_31bf3856ad364e35 [10.0.22621.2506] -> powershell.exe
wow64_microsoft-windows-printing-oleprn_31bf3856ad364e35 [10.0.22621.2506] -> oleprn.dll
wow64_microsoft-windows-printing-winrt-core_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.printing.dll
wow64_microsoft-windows-printing-workflow_31bf3856ad364e35 [10.0.22621.2506] -> print.printsupport.source.dll, print.workflow.source.dll, printworkflowservice.dll, windows.graphics.printing.workflow.dll, windows.graphics.printing.workflow.native.dll
wow64_microsoft-windows-printing-wsdahost_31bf3856ad364e35 [10.0.22621.2506] -> printwsdahost.dll
wow64_microsoft-windows-printing-xpsprint_31bf3856ad364e35 [10.0.22621.2506] -> xpsprint.dll
wow64_microsoft-windows-printing3d-winrt-core_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.printing.3d.dll
wow64_microsoft-windows-profapi-onecore_31bf3856ad364e35 [10.0.22621.2506] -> profapi.dll
wow64_microsoft-windows-propsys_31bf3856ad364e35 [7.0.22621.2506] -> propsys.dll
wow64_microsoft-windows-proquota_31bf3856ad364e35 [10.0.22621.2506] -> proquota.exe
wow64_microsoft-windows-provisioning-platform_31bf3856ad364e35 [10.0.22621.2506] -> provcmdlets.dll, provcommon.dll, provisioningcommandscsp.dll, provlaunch.exe, provmigrate.dll, provplatformdesktop.dll, wiminterop.dll
wow64_microsoft-windows-provisioningcore_31bf3856ad364e35 [10.0.22621.2506] -> provcore.dll
wow64_microsoft-windows-qwave_31bf3856ad364e35 [10.0.22621.2506] -> qwave.dll
wow64_microsoft-windows-r..-profile-hardwareid_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.profile.hardwareid.dll
wow64_microsoft-windows-r..ckgroundmediaplayer_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.backgroundmediaplayback.dll, windows.media.backgroundplayback.exe, windows.media.playback.backgroundmediaplayer.dll, windows.media.playback.mediaplayer.dll, windows.media.playback.proxystub.dll
wow64_microsoft-windows-r..sistance-dcomserver_31bf3856ad364e35 [10.0.22621.2506] -> raserver.exe
wow64_microsoft-windows-r..systemmanufacturers_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.profile.systemmanufacturers.dll
wow64_microsoft-windows-r..topservices-rdpbase_31bf3856ad364e35 [10.0.22621.2506] -> rdpbase.dll
wow64_microsoft-windows-rasrtutils_31bf3856ad364e35 [10.0.22621.2506] -> rtutils.dll
wow64_microsoft-windows-rasserver_31bf3856ad364e35 [10.0.22621.2506] -> iprtprio.dll, iprtrmgr.dll, mprdim.dll, rasmigplugin.dll, rtm.dll
wow64_microsoft-windows-rastls_31bf3856ad364e35 [10.0.22621.2506] -> rastlsext.dll
wow64_microsoft-windows-remoteassistance-exe_31bf3856ad364e35 [10.0.22621.2506] -> msra.exe, racpldlg.dll, sdchange.exe
wow64_microsoft-windows-resampledmo_31bf3856ad364e35 [10.0.22621.2506] -> resampledmo.dll
wow64_microsoft-windows-resourcemanager-client_31bf3856ad364e35 [10.0.22621.2506] -> rmclient.dll
wow64_microsoft-windows-retaildemo-retailinfo_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.profile.retailinfo.dll
wow64_microsoft-windows-riched32_31bf3856ad364e35 [10.0.22621.2506] -> riched20.dll, riched32.dll
wow64_microsoft-windows-rmcast_31bf3856ad364e35 [10.0.22621.2506] -> wshrm.dll
wow64_microsoft-windows-robocopy_31bf3856ad364e35 [10.0.22621.2506] -> robocopy.exe
wow64_microsoft-windows-rpc-http_31bf3856ad364e35 [10.0.22621.2506] -> rpchttp.dll
wow64_microsoft-windows-rpc-local_31bf3856ad364e35 [10.0.22621.2506] -> rpcrt4.dll
wow64_microsoft-windows-rpc-remote-extension_31bf3856ad364e35 [10.0.22621.2506] -> rpcrtremote.dll
wow64_microsoft-windows-runonce_31bf3856ad364e35 [10.0.22621.2506] -> runonce.exe
wow64_microsoft-windows-runtime-windows-media_31bf3856ad364e35 [10.0.22621.2715] * -> windows.media.dll
wow64_microsoft-windows-s..-credentialprovider_31bf3856ad364e35 [10.0.22621.2506] -> biocredprov.dll
wow64_microsoft-windows-s..-servicehostbuilder_31bf3856ad364e35 [10.0.22621.2506] -> windows.shell.servicehostbuilder.dll
wow64_microsoft-windows-s..-universal-internal_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.devices.sensors.dll
wow64_microsoft-windows-s..ardsubsystem-extras_31bf3856ad364e35 [10.0.22621.2506] -> scarddlg.dll
wow64_microsoft-windows-s..aryauthfactor-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.security.authentication.identity.provider.dll
wow64_microsoft-windows-s..ative-serverbox-isv_31bf3856ad364e35 [10.0.22621.2506] -> rmactivate_ssp_isv.exe, secproc_ssp_isv.dll
wow64_microsoft-windows-s..authfactor-credprov_31bf3856ad364e35 [10.0.22621.2506] -> devicengccredprov.dll
wow64_microsoft-windows-s..ces-targetedcontent_31bf3856ad364e35 [10.0.22621.2506] -> windows.services.targetedcontent.dll
wow64_microsoft-windows-s..configurationengine_31bf3856ad364e35 [10.0.22621.2506] -> scesrv.dll
wow64_microsoft-windows-s..csengine-nativehost_31bf3856ad364e35 [10.0.22621.2506] -> sdiagnhost.exe
wow64_microsoft-windows-s..ddriverprovider-dll_31bf3856ad364e35 [10.0.22621.2506] -> signdrv.dll
wow64_microsoft-windows-s..ementwmi-powershell_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.storage.core.dll, microsoft.windows.storage.storagebuscache.dll
wow64_microsoft-windows-s..engine-nativeengine_31bf3856ad364e35 [10.0.22621.2506] -> sdiageng.dll
wow64_microsoft-windows-s..entication-usermode_31bf3856ad364e35 [10.0.22621.2506] -> authz.dll
wow64_microsoft-windows-s..icate-policy-engine_31bf3856ad364e35 [10.0.22621.2506] -> certpoleng.dll
wow64_microsoft-windows-s..ity-netlogon-netapi_31bf3856ad364e35 [10.0.22621.2506] -> logoncli.dll
wow64_microsoft-windows-s..l-winuicohabitation_31bf3856ad364e35 [10.0.22621.2506] -> winuicohabitation.dll
wow64_microsoft-windows-s..lerevocationmanager_31bf3856ad364e35 [10.0.22621.2506] -> efswrt.dll
wow64_microsoft-windows-s..manager-service-api_31bf3856ad364e35 [10.0.22621.2506] -> licensemanagerapi.dll, tempsignedlicenseexchangetask.dll
wow64_microsoft-windows-s..mmoncommonproxystub_31bf3856ad364e35 [10.0.22621.2506] -> shellcommoncommonproxystub.dll
wow64_microsoft-windows-s..msettings-datamodel_31bf3856ad364e35 [10.0.22621.2715] * -> systemsettings.datamodel.dll
wow64_microsoft-windows-s..native-whitebox-isv_31bf3856ad364e35 [10.0.22621.2506] -> rmactivate_isv.exe, secproc_isv.dll
wow64_microsoft-windows-s..ngerprintcredential_31bf3856ad364e35 [10.0.22621.2506] -> fingerprintcredential.dll
wow64_microsoft-windows-s..on-brokerfiledialog_31bf3856ad364e35 [10.0.22621.2506] -> brokerfiledialog.dll
wow64_microsoft-windows-s..on-onlineid-runtime_31bf3856ad364e35 [10.0.22621.2506] -> windows.security.authentication.onlineid.dll
wow64_microsoft-windows-s..on-wizard-framework_31bf3856ad364e35 [10.0.22621.2506] -> spwizeng.dll, uxlib.dll, uxlibres.dll
wow64_microsoft-windows-s..rationmanagement-ui_31bf3856ad364e35 [10.0.22621.2506] -> wsecedit.dll
wow64_microsoft-windows-s..ryauthfactor-client_31bf3856ad364e35 [10.0.22621.2506] -> devicecredential.dll
wow64_microsoft-windows-s..sor-native-whitebox_31bf3856ad364e35 [10.0.22621.2506] -> rmactivate.exe, secproc.dll
wow64_microsoft-windows-s..spellcheck.binaries_31bf3856ad364e35 [10.0.22621.2506] -> msspellcheckingfacility.dll
wow64_microsoft-windows-s..stedsignal-credprov_31bf3856ad364e35 [10.0.22621.2506] -> trustedsignalcredprov.dll
wow64_microsoft-windows-s..ting-jscript9legacy_31bf3856ad364e35 [11.0.22621.2715] * -> jscript9legacy.dll
wow64_microsoft-windows-s..ty-cng-keyisolation_31bf3856ad364e35 [10.0.22621.2506] -> keyiso.dll
wow64_microsoft-windows-s..ty-integrity-policy_31bf3856ad364e35 [10.0.22621.2506] -> windows.security.integrity.dll
wow64_microsoft-windows-s..ty-kerbclientshared_31bf3856ad364e35 [10.0.22621.2506] -> kerbclientshared.dll
wow64_microsoft-windows-s..urationengineclient_31bf3856ad364e35 [10.0.22621.2506] -> scecli.dll
wow64_microsoft-windows-s..voicecommon-onecore_31bf3856ad364e35 [10.0.22621.2506] -> msttsengine_onecore.dll, msttsloc_onecore.dll
wow64_microsoft-windows-s..y-biometrics-client_31bf3856ad364e35 [10.0.22621.2506] -> winbio.dll
wow64_microsoft-windows-scripting-chakra_31bf3856ad364e35 [11.0.22621.2715] * -> chakra.dll, chakradiag.dll, chakrathunk.dll
wow64_microsoft-windows-scripting-jscript9_31bf3856ad364e35 [11.0.22621.2715] * -> jscript9.dll, jscript9diag.dll
wow64_microsoft-windows-scripting-jscript_31bf3856ad364e35 [11.0.22621.2506] -> jscript.dll
wow64_microsoft-windows-scripting-vbscript_31bf3856ad364e35 [11.0.22621.2506] -> vbscript.dll
wow64_microsoft-windows-scripting_31bf3856ad364e35 [10.0.22621.2506] -> cscript.exe, dispex.dll, scrobj.dll, scrrun.dll, wscript.exe, wshcon.dll, wshom.ocx
wow64_microsoft-windows-searchfolder-library_31bf3856ad364e35 [10.0.22621.2506] -> searchfolder.dll
wow64_microsoft-windows-sechost_31bf3856ad364e35 [10.0.22621.2506] -> sechost.dll
wow64_microsoft-windows-securestartup-core_31bf3856ad364e35 [10.0.22621.2506] -> fveapi.dll, fveapibase.dll
wow64_microsoft-windows-security-aadauthhelper_31bf3856ad364e35 [10.0.22621.2506] -> aadauthhelper.dll
wow64_microsoft-windows-security-aadtb_31bf3856ad364e35 [10.0.22621.2506] -> aadtb.dll
wow64_microsoft-windows-security-credssp_31bf3856ad364e35 [10.0.22621.2715] * -> credssp.dll, tspkg.dll
wow64_microsoft-windows-security-digest_31bf3856ad364e35 [10.0.22621.2715] * -> wdigest.dll
wow64_microsoft-windows-security-fido-credprov_31bf3856ad364e35 [10.0.22621.2506] -> fidocredprov.dll
wow64_microsoft-windows-security-identitystore_31bf3856ad364e35 [10.0.22621.2506] -> idstore.dll
wow64_microsoft-windows-security-kerberos_31bf3856ad364e35 [10.0.22621.2715] * -> kerberos.dll
wow64_microsoft-windows-security-negoexts_31bf3856ad364e35 [10.0.22621.2715] * -> negoexts.dll
wow64_microsoft-windows-security-netlogon_31bf3856ad364e35 [10.0.22621.2506] -> netlogon.dll
wow64_microsoft-windows-security-ngc-credprov_31bf3856ad364e35 [10.0.22621.2506] -> ngccredprov.dll
wow64_microsoft-windows-security-ngc-cryptngc_31bf3856ad364e35 [10.0.22621.2506] -> cryptngc.dll
wow64_microsoft-windows-security-ngc-hmkd_31bf3856ad364e35 [10.0.22621.2715] * -> hmkd.dll
wow64_microsoft-windows-security-ngc-keyenum_31bf3856ad364e35 [10.0.22621.2506] -> ngckeyenum.dll
wow64_microsoft-windows-security-ngc-ksp_31bf3856ad364e35 [10.0.22621.2506] -> ngcksp.dll
wow64_microsoft-windows-security-ngc-local_31bf3856ad364e35 [10.0.22621.2506] -> ngclocal.dll
wow64_microsoft-windows-security-noise_31bf3856ad364e35 [10.0.22621.2506] -> noise.dll
wow64_microsoft-windows-security-ntlm_31bf3856ad364e35 [10.0.22621.2715] * -> msv1_0.dll
wow64_microsoft-windows-security-ntlmshared_31bf3856ad364e35 [10.0.22621.2506] -> ntlmshared.dll
wow64_microsoft-windows-security-pku2u_31bf3856ad364e35 [10.0.22621.2715] * -> pku2u.dll
wow64_microsoft-windows-security-schannel_31bf3856ad364e35 [10.0.22621.2506] -> schannel.dll
wow64_microsoft-windows-security-spp-clientext_31bf3856ad364e35 [10.0.22621.2506] -> slcext.dll, sppcext.dll
wow64_microsoft-windows-security-spp-ux_31bf3856ad364e35 [10.0.22621.2506] -> devicereactivation.dll, editionupgradehelper.dll, editionupgrademanagerobj.dll, licensingwinrt.dll, sppcomapi.dll
wow64_microsoft-windows-security-spp_31bf3856ad364e35 [10.0.22621.2506] -> sppmig.dll
wow64_microsoft-windows-security-tokenbroker_31bf3856ad364e35 [10.0.22621.2506] -> tbauth.dll, tokenbroker.dll, tokenbrokercookies.exe, windows.security.authentication.web.core.dll
wow64_microsoft-windows-security-tokenbrokerui_31bf3856ad364e35 [10.0.22621.2506] -> tokenbrokerui.dll
wow64_microsoft-windows-security-vault_31bf3856ad364e35 [10.0.22621.2506] -> vaultcli.dll
wow64_microsoft-windows-security-webauthn_31bf3856ad364e35 [10.0.22621.2506] -> webauthn.dll
wow64_microsoft-windows-securitycenter-core_31bf3856ad364e35 [10.0.22621.2506] -> wscadminui.exe, wscapi.dll, wscisvif.dll, wscproxystub.dll
wow64_microsoft-windows-sendmail_31bf3856ad364e35 [10.0.22621.2506] -> sendmail.dll
wow64_microsoft-windows-sensors-core_31bf3856ad364e35 [10.0.22621.2506] -> sensorsnativeapi.dll, sensorsnativeapi.v2.dll, sensorsutilsv2.dll
wow64_microsoft-windows-sensors-universal_31bf3856ad364e35 [10.0.22621.2506] -> windows.devices.sensors.dll
wow64_microsoft-windows-servicingcommon_31bf3856ad364e35 [10.0.22621.2506] -> servicingcommon.dll
wow64_microsoft-windows-sethc_31bf3856ad364e35 [10.0.22621.2506] -> easeofaccessdialog.exe, sethc.exe
wow64_microsoft-windows-setupapi_31bf3856ad364e35 [10.0.22621.2506] -> setupapi.dll, wowreg32.exe
wow64_microsoft-windows-setupcl-library_31bf3856ad364e35 [10.0.22621.2506] -> setupcl.dll
wow64_microsoft-windows-sharedaccess_31bf3856ad364e35 [10.0.22621.2506] -> icsunattend.exe
wow64_microsoft-windows-shcore_31bf3856ad364e35 [10.0.22621.2715] * -> shcore.dll
wow64_microsoft-windows-shdocvw_31bf3856ad364e35 [10.0.22621.2506] -> shdocvw.dll
wow64_microsoft-windows-shell-setup_31bf3856ad364e35 [10.0.22621.2506] -> shsetup.dll
wow64_microsoft-windows-shell32_31bf3856ad364e35 [10.0.22621.2715] * -> shell32.dll
wow64_microsoft-windows-shenzhouttsvoicecommon_31bf3856ad364e35 [10.0.22621.2506] -> msttsengine.dll, msttsloc.dll
wow64_microsoft-windows-shlwapi_31bf3856ad364e35 [10.0.22621.2506] -> shlwapi.dll
wow64_microsoft-windows-smartcardksp_31bf3856ad364e35 [10.0.22621.2506] -> basecsp.dll, scksp.dll
wow64_microsoft-windows-smartcardplugins_31bf3856ad364e35 [10.0.22621.2506] -> msclmd.dll
wow64_microsoft-windows-smartscreen_31bf3856ad364e35 [10.0.22621.2506] -> smartscreen.dll, smartscreenps.dll
wow64_microsoft-windows-smbserver-netapi_31bf3856ad364e35 [10.0.22621.2506] -> srvcli.dll
wow64_microsoft-windows-smbserver_31bf3856ad364e35 [10.0.22621.2506] -> sscore.dll
wow64_microsoft-windows-spatialinteraction_31bf3856ad364e35 [10.0.22621.2506] -> spatialinteraction.dll
wow64_microsoft-windows-speech-pal-desktop_31bf3856ad364e35 [10.0.22621.2506] -> windows.speech.pal.desktop.dll
wow64_microsoft-windows-speech-shell_31bf3856ad364e35 [10.0.22621.2506] -> windows.speech.dictation.dll, windows.speech.shell.dll
wow64_microsoft-windows-speechcommon-onecore_31bf3856ad364e35 [10.0.22621.2506] -> sapi_onecore.dll, speechmodeldownload.exe
wow64_microsoft-windows-speechcommon_31bf3856ad364e35 [10.0.22621.2506] -> sapi.dll
wow64_microsoft-windows-speechengine-onecore_31bf3856ad364e35 [10.0.22621.2506] -> spsreng_onecore.dll, spsrx_onecore.dll
wow64_microsoft-windows-stobject_31bf3856ad364e35 [10.0.22621.2506] -> stobject.dll
wow64_microsoft-windows-storage-diagnostics_31bf3856ad364e35 [10.0.22621.2506] -> stordiag.exe
wow64_microsoft-windows-storage-search-library_31bf3856ad364e35 [10.0.22621.2506] -> windows.storage.search.dll
wow64_microsoft-windows-storagemanagementwmi_31bf3856ad364e35 [10.0.22621.2506] -> delegatorprovider.dll, storagewmi.dll, storagewmi_passthru.dll
wow64_microsoft-windows-storageservice_31bf3856ad364e35 [10.0.22621.2506] -> storageusage.dll
wow64_microsoft-windows-store-install-service_31bf3856ad364e35 [10.0.22621.2506] -> installservice.dll, installservicetasks.dll
wow64_microsoft-windows-store-licensemanager_31bf3856ad364e35 [10.0.22621.2506] -> licensemanager.dll
wow64_microsoft-windows-store-runtime_31bf3856ad364e35 [10.0.22621.2506] -> windows.applicationmodel.store.dll, windows.applicationmodel.store.testingframework.dll
wow64_microsoft-windows-streambufferengine_31bf3856ad364e35 [10.0.22621.2506] -> sbe.dll, sbeio.dll
wow64_microsoft-windows-sud_31bf3856ad364e35 [10.0.22621.2506] -> sud.dll
wow64_microsoft-windows-syncsettings_31bf3856ad364e35 [10.0.22621.2506] -> syncsettings.dll
wow64_microsoft-windows-sysprep-spbcd_31bf3856ad364e35 [10.0.22621.2506] -> spbcd.dll
wow64_microsoft-windows-systemmanagement_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.systemmanagement.dll
wow64_microsoft-windows-t..-coreinkrecognition_31bf3856ad364e35 [10.0.22621.2506] -> mshwlatin.dll
wow64_microsoft-windows-t..andinkinputservices_31bf3856ad364e35 [10.0.22621.2506] -> tiptsf.dll
wow64_microsoft-windows-t..atform-input-ninput_31bf3856ad364e35 [10.0.22621.2506] -> ninput.dll
wow64_microsoft-windows-t..boration-sharer-api_31bf3856ad364e35 [10.0.22621.2506] -> rdpsharercom.dll
wow64_microsoft-windows-t..cesframework-msctfp_31bf3856ad364e35 [10.0.22621.2506] -> msctfp.dll
wow64_microsoft-windows-t..duler-compatibility_31bf3856ad364e35 [10.0.22621.2506] -> taskcomp.dll
wow64_microsoft-windows-t..es-workspace-radcui_31bf3856ad364e35 [10.0.22621.2506] -> radcui.dll
wow64_microsoft-windows-t..icesframework-msctf_31bf3856ad364e35 [10.0.22621.2506] -> msctf.dll
wow64_microsoft-windows-t..icesframework-msutb_31bf3856ad364e35 [10.0.22621.2506] -> msutb.dll
wow64_microsoft-windows-t..lservices-workspace_31bf3856ad364e35 [10.0.22621.2506] -> tsworkspace.dll
wow64_microsoft-windows-t..mework-msctfmonitor_31bf3856ad364e35 [10.0.22621.2506] -> msctfmonitor.dll
wow64_microsoft-windows-t..mework-uimanagerdll_31bf3856ad364e35 [10.0.22621.2506] -> msctfuimanager.dll
wow64_microsoft-windows-t..minalservicesclient_31bf3856ad364e35 [10.0.22621.2506] -> mstsc.exe
wow64_microsoft-windows-t..nalservices-runtime_31bf3856ad364e35 [10.0.22621.2506] -> winsta.dll
wow64_microsoft-windows-t..nkrecognition.ja-jp_31bf3856ad364e35 [10.0.22621.2506] -> dicjp.dll, imjplm.dll, mshwjpn.dll, mshwjpnr.dll
wow64_microsoft-windows-t..nkrecognition.ko-kr_31bf3856ad364e35 [10.0.22621.2506] -> mshwkor.dll, mshwkorr.dll
wow64_microsoft-windows-t..nkrecognition.zh-cn_31bf3856ad364e35 [10.0.22621.2506] -> mshwchs.dll, mshwchsr.dll
wow64_microsoft-windows-t..nkrecognition.zh-tw_31bf3856ad364e35 [10.0.22621.2506] -> mshwcht.dll, mshwchtr.dll
wow64_microsoft-windows-t..ormabstractionlayer_31bf3856ad364e35 [10.0.22621.2506] -> phoneplatformabstraction.dll
wow64_microsoft-windows-t..platform-comruntime_31bf3856ad364e35 [10.0.22621.2506] -> inkdiv.dll, inked.dll, inkobj.dll, rtscom.dll
wow64_microsoft-windows-t..r-decodingresources_31bf3856ad364e35 [10.0.22621.2506] -> tdhres.dll
wow64_microsoft-windows-t..s-clientactivexcore_31bf3856ad364e35 [10.0.22621.2506] -> mstscax.dll, tsgqec.dll
wow64_microsoft-windows-t..s-sessionenvservice_31bf3856ad364e35 [10.0.22621.2506] -> rdvvmtransport.dll, sessenv.dll
wow64_microsoft-windows-t..sframework-inputdll_31bf3856ad364e35 [10.0.22621.2506] -> input.dll
wow64_microsoft-windows-tabletpc-inputpanel_31bf3856ad364e35 [10.0.22621.2506] -> tabtip32.exe
wow64_microsoft-windows-tapi3_31bf3856ad364e35 [10.0.22621.2506] -> tapi3.dll, wavemsp.dll
wow64_microsoft-windows-taskscheduler-netapi_31bf3856ad364e35 [10.0.22621.2506] -> schedcli.dll
wow64_microsoft-windows-tcpip-utility_31bf3856ad364e35 [10.0.22621.2506] -> arp.exe, finger.exe, hostname.exe, mrinfo.exe, netiohlp.dll, netstat.exe, route.exe, tcpsvcs.exe
wow64_microsoft-windows-telemetrypermission_31bf3856ad364e35 [10.0.22621.2506] -> diagnosticdatasettings.dll
wow64_microsoft-windows-textinputframework_31bf3856ad364e35 [10.0.22621.2506] -> textinputframework.dll
wow64_microsoft-windows-themecpl_31bf3856ad364e35 [10.0.22621.2506] -> themecpl.dll
wow64_microsoft-windows-themeui_31bf3856ad364e35 [10.0.22621.2506] -> themeui.dll
wow64_microsoft-windows-thumbnailcache_31bf3856ad364e35 [10.0.22621.2506] -> thumbcache.dll
wow64_microsoft-windows-tpm-coreprovisioning_31bf3856ad364e35 [10.0.22621.2506] -> tpmcertresources.dll, tpmcoreprovisioning.dll
wow64_microsoft-windows-tpm-tbs_31bf3856ad364e35 [10.0.22621.2506] -> tbs.dll
wow64_microsoft-windows-tpm-tool_31bf3856ad364e35 [10.0.22621.2506] -> tpmtool.exe
wow64_microsoft-windows-twext_31bf3856ad364e35 [10.0.22621.2506] -> twext.dll
wow64_microsoft-windows-twinapi-appcore_31bf3856ad364e35 [10.0.22621.2506] -> twinapi.appcore.dll
wow64_microsoft-windows-twinapi_31bf3856ad364e35 [10.0.22621.2506] -> twinapi.dll
wow64_microsoft-windows-twinui-appcore_31bf3856ad364e35 [10.0.22621.2506] -> twinui.appcore.dll
wow64_microsoft-windows-twinui_31bf3856ad364e35 [10.0.22621.2506] -> launchwinapp.exe, twinui.dll
wow64_microsoft-windows-u..access-unifiedstore_31bf3856ad364e35 [10.0.22621.2506] -> unistore.dll
wow64_microsoft-windows-u..access-userdataapis_31bf3856ad364e35 [10.0.22621.2506] -> appointmentapis.dll, chatapis.dll, contactapis.dll, emailapis.dll, peopleapis.dll, phonecallhistoryapis.dll, taskapis.dll, userdataaccountapis.dll
wow64_microsoft-windows-u..ccess-userdatautils_31bf3856ad364e35 [10.0.22621.2506] -> addressparser.dll, appointmentactivation.dll, contactactivation.dll, exsmime.dll, extrasxmlparser.dll, posyncservices.dll, userdataaccessres.dll, userdatalanguageutil.dll, userdataplatformhelperutil.dll, userdatatimeutil.dll, userdatatypehelperutil.dll, vcardparser.dll
wow64_microsoft-windows-u..eclient-aux-preview_31bf3856ad364e35 [10.0.22621.2506] -> wuapicore.dll, wupscore.dll, wutrust.dll
wow64_microsoft-windows-u..etry-client-wowonly_31bf3856ad364e35 [10.0.22621.2506] -> diagnosticdataquery.dll, dtdump.exe, utcapi.dll
wow64_microsoft-windows-u..ll-windowtabmanager_31bf3856ad364e35 [10.0.22621.2506] -> windows.internal.ui.shell.windowtabmanager.dll
wow64_microsoft-windows-u..ountcontrolsettings_31bf3856ad364e35 [10.0.22621.2506] -> useraccountcontrolsettings.dll, useraccountcontrolsettings.exe
wow64_microsoft-windows-ucrt_31bf3856ad364e35 [10.0.22621.2506] -> msvcp_win.dll, ucrtbase.dll
wow64_microsoft-windows-ui-cred-library_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.cred.dll
wow64_microsoft-windows-ui-fileexplorer-wasdk_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.fileexplorer.wasdk.dll
wow64_microsoft-windows-ui-fileexplorer_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.fileexplorer.dll
wow64_microsoft-windows-ui-search_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.search.dll
wow64_microsoft-windows-ui-xaml-controls_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xaml.controls.dll
wow64_microsoft-windows-ui-xaml-inkcontrols_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xaml.inkcontrols.dll
wow64_microsoft-windows-ui-xaml-maps_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xaml.maps.dll
wow64_microsoft-windows-ui-xaml-phone_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xaml.phone.dll
wow64_microsoft-windows-uiautomationcore_31bf3856ad364e35 [10.0.22621.2506] -> uiautomationcore.dll
wow64_microsoft-windows-uiribbon_31bf3856ad364e35 [10.0.22621.2506] -> uiribbon.dll
wow64_microsoft-windows-undockeddevkit_31bf3856ad364e35 [10.0.22621.2506] -> windowsudk.shellcommon.dll
wow64_microsoft-windows-update-orchestratorapi_31bf3856ad364e35 [10.0.22621.2506] -> usoapi.dll
wow64_microsoft-windows-update-uus-stable_31bf3856ad364e35 [10.0.22621.2506] -> uusbrain.dll
wow64_microsoft-windows-update-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.management.update.dll
wow64_microsoft-windows-upnpdevicehost_31bf3856ad364e35 [10.0.22621.2506] -> udhisapi.dll, upnpcont.exe, upnphost.dll
wow64_microsoft-windows-upnpssdp-server_31bf3856ad364e35 [10.0.22621.2506] -> ssdpapi.dll
wow64_microsoft-windows-upnpssdp_31bf3856ad364e35 [10.0.22621.2506] -> ssdpapi.dll
wow64_microsoft-windows-user32_31bf3856ad364e35 [10.0.22621.2506] -> user32.dll
wow64_microsoft-windows-useractivitybroker_31bf3856ad364e35 [10.0.22621.2506] -> useractivitybroker.dll
wow64_microsoft-windows-usercpl_31bf3856ad364e35 [10.0.22621.2506] -> usercpl.dll
wow64_microsoft-windows-userdeviceregistration_31bf3856ad364e35 [10.0.22621.2506] -> dsreg.dll, userdeviceregistration.dll, userdeviceregistration.ngc.dll
wow64_microsoft-windows-userenv_31bf3856ad364e35 [10.0.22621.2506] -> userenv.dll
wow64_microsoft-windows-userenvext_31bf3856ad364e35 [10.0.22621.2506] -> profext.dll
wow64_microsoft-windows-userinit_31bf3856ad364e35 [10.0.22621.2506] -> userinit.exe
wow64_microsoft-windows-userpowermanagement_31bf3856ad364e35 [10.0.22621.2506] -> powrprof.dll
wow64_microsoft-windows-utilman_31bf3856ad364e35 [10.0.22621.2506] -> utilman.exe
wow64_microsoft-windows-uus-infra-core-preview_31bf3856ad364e35 [10.0.22621.2506] -> uusbrain.dll
wow64_microsoft-windows-uxinit_31bf3856ad364e35 [10.0.22621.2506] -> uxinit.dll
wow64_microsoft-windows-uxtheme_31bf3856ad364e35 [10.0.22621.2506] -> uxtheme.dll
wow64_microsoft-windows-v..e-filters-tvdigital_31bf3856ad364e35 [10.0.22621.2506] -> psisdecd.dll
wow64_microsoft-windows-v..payloadrestrictions_31bf3856ad364e35 [10.0.22621.2506] -> payloadrestrictions.dll
wow64_microsoft-windows-van_31bf3856ad364e35 [10.0.22621.2506] -> van.dll
wow64_microsoft-windows-video-for-windows_31bf3856ad364e35 [10.0.22621.2506] -> avicap32.dll, avifil32.dll, mciavi32.dll, msrle32.dll, msvfw32.dll, msvidc32.dll
wow64_microsoft-windows-vidproc_31bf3856ad364e35 [10.0.22621.2506] -> msvproc.dll
wow64_microsoft-windows-virtualdiskapilibrary_31bf3856ad364e35 [10.0.22621.2506] -> virtdisk.dll
wow64_microsoft-windows-w..-chinese_simplified_31bf3856ad364e35 [10.0.22621.2506] -> mswb70804.dll, nl7data0804.dll
wow64_microsoft-windows-w..-infrastructure-bsp_31bf3856ad364e35 [10.0.22621.2506] -> mswsock.dll
wow64_microsoft-windows-w..-system-diagnostics_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.diagnostics.dll
wow64_microsoft-windows-w..ationservice-netapi_31bf3856ad364e35 [10.0.22621.2506] -> wkscli.dll
wow64_microsoft-windows-w..chinese_traditional_31bf3856ad364e35 [10.0.22621.2506] -> mswb70404.dll, nl7data0404.dll
wow64_microsoft-windows-w..emassessmenttoolapi_31bf3856ad364e35 [10.0.22621.2506] -> winsatapi.dll
wow64_microsoft-windows-w..for-management-core_31bf3856ad364e35 [10.0.22621.2506] -> wsmagent.dll, wsmanhttpconfig.exe, wsmanmigrationplugin.dll, wsmauto.dll, wsmplpxy.dll, wsmprovhost.exe, wsmres.dll, wsmsvc.dll, wsmwmipl.dll
wow64_microsoft-windows-w..ig-registrar-wizard_31bf3856ad364e35 [10.0.22621.2506] -> wcnwiz.dll
wow64_microsoft-windows-w..indowsuiinputinking_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.input.inking.dll
wow64_microsoft-windows-w..owsupdateclient-aux_31bf3856ad364e35 [10.0.22621.2506] -> wuapi.dll, wuapicore.dll, wups.dll, wupscore.dll, wusys.dll, wutrust.dll
wow64_microsoft-windows-w..r7-mswb7ea-japanese_31bf3856ad364e35 [10.0.22621.2506] -> mswb70011.dll, nl7data0011.dll
wow64_microsoft-windows-w..sition-coreservices_31bf3856ad364e35 [10.0.22621.2506] -> sti.dll, wiatrace.dll
wow64_microsoft-windows-w..utinking-inkobjcore_31bf3856ad364e35 [10.0.22621.2506] -> inkobjcore.dll
wow64_microsoft-windows-wab-core_31bf3856ad364e35 [10.0.22621.2506] -> wab32.dll, wab32res.dll, wabimp.dll
wow64_microsoft-windows-web-app-host-api_31bf3856ad364e35 [10.0.22621.2506] -> wwaapi.dll
wow64_microsoft-windows-web-app-host_31bf3856ad364e35 [10.0.22621.2506] -> wwahost.exe
wow64_microsoft-windows-web-http_31bf3856ad364e35 [10.0.22621.2506] -> windows.web.http.dll
wow64_microsoft-windows-webio_31bf3856ad364e35 [10.0.22621.2506] -> webio.dll
wow64_microsoft-windows-webp-image-codec_31bf3856ad364e35 [10.0.22621.2506] -> mswebp.dll
wow64_microsoft-windows-wer-sdktools_31bf3856ad364e35 [10.0.22621.2506] -> dbgeng.dll, dbgmodel.dll
wow64_microsoft-windows-wifidisplay_31bf3856ad364e35 [10.0.22621.2506] -> wifidisplay.dll
wow64_microsoft-windows-wimgapi_31bf3856ad364e35 [10.0.22621.2506] -> wimgapi.dll
wow64_microsoft-windows-win32k_31bf3856ad364e35 [10.0.22621.2506] -> win32u.dll
wow64_microsoft-windows-wincredui_31bf3856ad364e35 [10.0.22621.2506] -> wincredui.dll
wow64_microsoft-windows-windowscodec_31bf3856ad364e35 [10.0.22621.2506] -> windowscodecs.dll
wow64_microsoft-windows-windowsstorage-onecore_31bf3856ad364e35 [10.0.22621.2506] -> windows.storage.onecore.dll
wow64_microsoft-windows-windowsuiimmersive_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.immersive.dll
wow64_microsoft-windows-windowui_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.dll
wow64_microsoft-windows-wininit_31bf3856ad364e35 [10.0.22621.2506] -> wmsgapi.dll
wow64_microsoft-windows-winre-recoveryagent_31bf3856ad364e35 [10.0.22621.2506] -> reagent.dll, reinfo.dll
wow64_microsoft-windows-winre-recoverytools_31bf3856ad364e35 [10.0.22621.2506] -> reagentc.exe
wow64_microsoft-windows-winrt-metadata_31bf3856ad364e35 [10.0.22621.2506] -> rometadata.dll
wow64_microsoft-windows-winrt-windowsgraphics_31bf3856ad364e35 [10.0.22621.2506] -> windows.graphics.dll
wow64_microsoft-windows-wintrust-dll_31bf3856ad364e35 [10.0.22621.2506] -> wintrust.dll
wow64_microsoft-windows-wlanconnectionflow_31bf3856ad364e35 [10.0.22621.2506] -> wlanconn.dll
wow64_microsoft-windows-wlangpui_31bf3856ad364e35 [10.0.22621.2506] -> wlangpui.dll
wow64_microsoft-windows-wlanmediamanager_31bf3856ad364e35 [10.0.22621.2506] -> wlanmm.dll
wow64_microsoft-windows-wmadmod_31bf3856ad364e35 [10.0.22621.2506] -> wmadmod.dll
wow64_microsoft-windows-wmi-core-fastprox-dll_31bf3856ad364e35 [10.0.22621.2506] -> fastprox.dll
wow64_microsoft-windows-wmi-core-wbemcomn-dll_31bf3856ad364e35 [10.0.22621.2506] -> wbemcomn.dll
wow64_microsoft-windows-wmi-core-wbemcore-dll_31bf3856ad364e35 [10.0.22621.2506] -> wbemcore.dll
wow64_microsoft-windows-wmi-core_31bf3856ad364e35 [10.0.22621.2506] -> esscli.dll, framedynos.dll, mofcomp.exe, mofd.dll, ncobjapi.dll, wbemprox.dll, wbemsvc.dll, wmiadap.exe, wmicookr.dll, wmimigrationplugin.dll, wmiutils.dll
wow64_microsoft-windows-wmpnss-api_31bf3856ad364e35 [10.0.22621.2506] -> wmpnssci.dll
wow64_microsoft-windows-wmpnss-publicapi_31bf3856ad364e35 [10.0.22621.2506] -> wmpmediasharing.dll
wow64_microsoft-windows-wmspdmod_31bf3856ad364e35 [10.0.22621.2506] -> wmspdmod.dll
wow64_microsoft-windows-wmvdecod_31bf3856ad364e35 [10.0.22621.2506] -> wmvdecod.dll
wow64_microsoft-windows-wmviddsp_31bf3856ad364e35 [10.0.22621.2506] -> colorcnv.dll, vidreszr.dll
wow64_microsoft-windows-workplace_31bf3856ad364e35 [10.0.22621.2506] -> windows.management.workplace.dll
wow64_microsoft-windows-wpd-shellextension_31bf3856ad364e35 [10.0.22621.2715] * -> wpdshext.dll, wpdshextautoplay.exe, wpdshserviceobj.dll
wow64_microsoft-windows-wrp-integrity-client_31bf3856ad364e35 [10.0.22621.2506] -> sfc.exe
wow64_microsoft-windows-wsp-fileserver_31bf3856ad364e35 [10.0.22621.2506] -> wsp_fs.dll
wow64_microsoft-windows-wsp-health_31bf3856ad364e35 [10.0.22621.2506] -> wsp_health.dll
wow64_microsoft-windows-wsp-replication_31bf3856ad364e35 [10.0.22621.2506] -> wsp_sr.dll
wow64_microsoft-windows-wsp-spaces_31bf3856ad364e35 [10.0.22621.2506] -> mispace.dll, smphost.dll
wow64_microsoft-windows-wwan-lpa-api_31bf3856ad364e35 [10.0.22621.2506] -> windows.networking.networkoperators.esim.dll
wow64_microsoft-windows-x..rtificateenrollment_31bf3856ad364e35 [10.0.22621.2506] -> certenroll.dll, certenrollctrl.exe
wow64_microsoft-windows-xamlhost-library_31bf3856ad364e35 [10.0.22621.2506] -> windows.ui.xamlhost.dll
wow64_microsoft-windows-xmllite_31bf3856ad364e35 [10.0.22621.2506] -> xmllite.dll
wow64_microsoft-windows-xpsifilter_31bf3856ad364e35 [10.0.22621.2506] -> xpsfilt.dll
wow64_microsoft-windows-xpsreachviewer_31bf3856ad364e35 [10.0.22621.2506] -> xpsrchvw.exe
wow64_microsoft-windows-zipfldr_31bf3856ad364e35 [10.0.22621.2715] * -> zipfldr.dll
wow64_microsoft-windowscore-coreglobconfig_31bf3856ad364e35 [10.0.22621.2506] -> coreglobconfig.dll
wow64_microsoft-xbox-auth..er-client-component_31bf3856ad364e35 [10.0.22621.2506] -> xblauthmanagerproxy.dll, xblauthtokenbrokerext.dll
wow64_microsoft-xbox-gameoverlay_31bf3856ad364e35 [10.0.22621.2506] -> gamepanel.exe, gamepanelexternalhook.dll
wow64_microsoft.appv.appvclientcomconsumer_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.appv.appvclientcomconsumer.dll
wow64_microsoft.backgroun..r.management.module_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.backgroundintelligenttransfer.management.interop.dll
wow64_microsoft.certifica..s.pkiclient.cmdlets_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.certificateservices.pkiclient.cmdlets.dll
wow64_microsoft.configci.commands.resources_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.configci.commands.resources.dll
wow64_microsoft.configci.commands_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.configci.commands.dll
wow64_microsoft.keydistributionservice.cmdlets_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.keydistributionservice.cmdlets.dll
wow64_microsoft.windows.gdiplus.systemcopy_31bf3856ad364e35 [10.0.22621.2506] -> gdiplus.dll
wow64_microsoft.windows.winhttp_31bf3856ad364e35 [5.1.22621.2506] -> winhttp.dll
wow64_microsoft.windowsau..nprotocols.commands_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windowsauthenticationprotocols.commands.dll
wow64_multimedia-windows-..rotection-playready_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.protection.playready.dll
wow64_napcrypt_31bf3856ad364e35 [10.0.22621.2506] -> napcrypt.dll
wow64_networking-mpssvc-admin.resources_31bf3856ad364e35 [10.0.22621.2506] -> authfwsnapin.resources.dll, authfwwizfwk.resources.dll
wow64_networking-mpssvc-admin_31bf3856ad364e35 [10.0.22621.2506] -> authfwgp.dll, authfwsnapin.dll, authfwwizfwk.dll
wow64_networking-mpssvc-netsh_31bf3856ad364e35 [10.0.22621.2506] -> authfwcfg.dll, checknetisolation.exe, fwcfg.dll, nshwfp.dll
wow64_networking-mpssvc-p..l-windows.resources_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.firewall.commands.resources.dll
wow64_networking-mpssvc-powershell-windows_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.windows.firewall.commands.dll
wow64_networking-mpssvc-svc_31bf3856ad364e35 [10.0.22621.2506] -> firewallapi.dll, fwbase.dll, fwpolicyiomgr.dll, wfapigp.dll
wow64_product-containeros__windowssearchengine_31bf3856ad364e35 [7.0.22621.2506] -> msscntrs.dll, mssitlb.dll, mssph.dll, mssprxy.dll, mssrch.dll, mssvp.dll, search.protocolhandler.mapi2.dll, searchfilterhost.exe, searchindexer.exe, searchindexercore.dll, searchprotocolhost.exe, tquery.dll, wsearchmigplugin.dll
wow64_product-onecore__mi..ft-windows-wmspdmod_31bf3856ad364e35 [10.0.22621.2506] -> wmspdmod.dll
wow64_product-onecore__mi..ft-windows-wmvdecod_31bf3856ad364e35 [10.0.22621.2506] -> wmvdecod.dll
wow64_product-onecore__mi..ndows-mfmpeg2srcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfmpeg2srcsnk.dll
wow64_product-onecore__mi..oft-windows-wmadmod_31bf3856ad364e35 [10.0.22621.2506] -> wmadmod.dll
wow64_product-onecore__mi..onentpackagesupport_31bf3856ad364e35 [10.0.22621.2506] -> comppkgsup.dll
wow64_product-onecore__mi..soft-windows-mfcore_31bf3856ad364e35 [10.0.22621.2506] -> mfcore.dll, mfps.dll
wow64_product-onecore__mi..windows-mfasfsrcsnk_31bf3856ad364e35 [10.0.22621.2506] -> mfasfsrcsnk.dll
wow64_product-onecore__mi..windows-msauddecmft_31bf3856ad364e35 [10.0.22621.2506] -> msauddecmft.dll
wow64_product-onecore__mi..windows-msmpeg2vdec_31bf3856ad364e35 [10.0.22621.2506] -> msmpeg2vdec.dll
wow64_tenantrestrictions-plugin_31bf3856ad364e35 [10.0.22621.2506] -> tenantrestrictionsplugin.dll
wow64_windows-application..-appcontracts-winrt_31bf3856ad364e35 [10.0.22621.2506] -> appcontracts.dll
wow64_windows-applicationmodel-clipboardserver_31bf3856ad364e35 [10.0.22621.2506] -> clipboardserver.dll
wow64_windows-applicationmodel_31bf3856ad364e35 [10.0.22621.2506] -> windows.applicationmodel.dll
wow64_windows-gaming-input-synthetic_31bf3856ad364e35 [10.0.22621.2506] -> xboxgipsynthetic.dll
wow64_windows-gaming-input-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.gaming.input.dll, xinputuap.dll
wow64_windows-id-connecte..-provider-tokenprov_31bf3856ad364e35 [10.0.22621.2506] -> microsoftaccounttokenprovider.dll
wow64_windows-id-connecte..nt-provider-activex_31bf3856ad364e35 [10.0.22621.2506] -> windowslivelogin.dll
wow64_windows-id-connecte..nt-provider-wlidcli_31bf3856ad364e35 [10.0.22621.2506] -> wlidcli.dll
wow64_windows-id-connecte..nt-provider-wlidfdp_31bf3856ad364e35 [10.0.22621.2506] -> wlidfdp.dll
wow64_windows-id-connecte..nt-provider-wlidnsp_31bf3856ad364e35 [10.0.22621.2506] -> wlidnsp.dll
wow64_windows-id-connecte..ovider-wlidcredprov_31bf3856ad364e35 [10.0.22621.2506] -> wlidcredprov.dll
wow64_windows-id-connecte..t-provider-wlidprov_31bf3856ad364e35 [10.0.22621.2506] -> wlidprov.dll
wow64_windows-media-speech-winrt_31bf3856ad364e35 [10.0.22621.2506] -> windows.media.speech.dll
wow64_windows-staterepository_31bf3856ad364e35 [10.0.22621.2506] -> staterepository.core.dll, windows.staterepository.dll, windows.staterepositorybroker.dll, windows.staterepositoryclient.dll, windows.staterepositorycore.dll, windows.staterepositoryps.dll, windows.staterepositoryupgrade.dll
wow64_windows-system-launcher_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.launcher.dll
wow64_windows-system-prof..ndusagedatasettings_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.profile.platformdiagnosticsandusagedatasettings.dll
wow64_windows-system-user..diagnosticssettings_31bf3856ad364e35 [10.0.22621.2506] -> windows.system.userprofile.diagnosticssettings.dll
wow64_windows.networking.vpn_31bf3856ad364e35 [10.0.22621.2506] -> cmintegrator.dll, windows.networking.vpn.dll
wow64_windowsdeviceportal_31bf3856ad364e35 [10.0.22621.2506] -> wdp.dll
wow64_windowssearchengine-structuredquery_31bf3856ad364e35 [7.0.22621.2506] -> structuredquery.dll
wow64_windowssearchengine_31bf3856ad364e35 [7.0.22621.2506] -> msscntrs.dll, mssitlb.dll, mssph.dll, mssprxy.dll, mssrch.dll, mssvp.dll, search.protocolhandler.mapi2.dll, searchfilterhost.exe, searchindexer.exe, searchindexercore.dll, searchprotocolhost.exe, tquery.dll, wsearchmigplugin.dll
x86_dual_ntprint.inf_31bf3856ad364e35 [10.0.22621.2506] -> mxdwdrv.dll, pcl4res.dll, pcl5eres.dll, pcl5ures.dll, pclxl.dll, pjlmon.dll, ps5ui.dll, pscript5.dll, unidrv.dll, unidrvui.dll, unires.dll
x86_dual_prnms003.inf_31bf3856ad364e35 [10.0.22621.2715] * -> printconfig.dll
x86_microsoft-windows-a..c-performance-layer_31bf3856ad364e35 [10.0.22621.2506] -> dmband.dll, dmcompos.dll, dmime.dll, dmscript.dll, dmstyle.dll
x86_microsoft-windows-b..re-bootmanager-pcat_31bf3856ad364e35 [10.0.22621.2715] * -> bootspaces.dll, bootuwf.dll, bootvhd.dll
x86_microsoft-windows-bootenvironment-pxe_31bf3856ad364e35 [10.0.22621.2506] -> bootmgr.exe
x86_microsoft-windows-com-dtc-oraclesupport_31bf3856ad364e35 [10.0.22621.2506] -> mtxoci.dll
x86_microsoft-windows-com-legacyole-olecli32_31bf3856ad364e35 [10.0.22621.2506] -> olecli32.dll
x86_microsoft-windows-com-legacyole_31bf3856ad364e35 [10.0.22621.2506] -> iprop.dll, olesvr32.dll, olethk32.dll
x86_microsoft-windows-cpfilters_31bf3856ad364e35 [10.0.22621.2715] * -> cpfilters.dll
x86_microsoft-windows-d..-commandline-dsdiag_31bf3856ad364e35 [10.0.22621.2506] -> dcdiag.exe
x86_microsoft-windows-d..-commandline-dsmgmt_31bf3856ad364e35 [10.0.22621.2506] -> dsmgmt.exe
x86_microsoft-windows-d..-winproviders-winpe_31bf3856ad364e35 [10.0.22621.2506] -> peprovider.dll
x86_microsoft-windows-d..ommandline-dsdbutil_31bf3856ad364e35 [10.0.22621.2506] -> dsdbutil.exe
x86_microsoft-windows-d..ommandline-repadmin_31bf3856ad364e35 [10.0.22621.2506] -> repadmin.exe
x86_microsoft-windows-ie-ieproxy_31bf3856ad364e35 [11.0.22621.2506] -> ieproxy.dll
x86_microsoft-windows-ie-ieshims_31bf3856ad364e35 [11.0.22621.2506] -> ieshims.dll
x86_microsoft-windows-ie-mshtmldac_31bf3856ad364e35 [11.0.22621.2506] -> mshtmldac.dll
x86_microsoft-windows-ie-vgx_31bf3856ad364e35 [11.0.22621.2506] -> vgx.dll
x86_microsoft-windows-m..commonresource-core_31bf3856ad364e35 [10.0.22621.2506] -> mqutil.dll
x86_microsoft-windows-mediaplayer-wmvcore_31bf3856ad364e35 [10.0.22621.2506] -> wmvcore.dll
x86_microsoft-windows-msac3enc_31bf3856ad364e35 [10.0.22621.2506] -> msac3enc.dll
x86_microsoft-windows-msmpeg2enc_31bf3856ad364e35 [10.0.22621.2506] -> msmpeg2enc.dll
x86_microsoft-windows-msmq-admin_31bf3856ad364e35 [10.0.22621.2506] -> mqcertui.dll, mqsnap.dll
x86_microsoft-windows-msmq-installer_31bf3856ad364e35 [10.0.22621.2506] -> mqad.dll, mqcmiplugin.dll, mqmigplugin.dll, mqsec.dll
x86_microsoft-windows-msmq-powershell_31bf3856ad364e35 [10.0.22621.2715] * -> microsoft.msmq.activex.interop.dll, microsoft.msmq.powershell.commands.dll, microsoft.msmq.runtime.interop.dll
x86_microsoft-windows-msmq-runtime-core_31bf3856ad364e35 [10.0.22621.2506] -> mqrt.dll
x86_microsoft-windows-msmq-runtime_31bf3856ad364e35 [10.0.22621.2506] -> mqoa.dll
x86_microsoft-windows-rasmprsnap_31bf3856ad364e35 [10.0.22621.2506] -> mprsnap.dll
x86_microsoft-windows-rasppp-noneap_31bf3856ad364e35 [10.0.22621.2506] -> rasppp.dll
x86_microsoft-windows-s..-installers-onecore_31bf3856ad364e35 [10.0.22621.2567] -> appxprovisionpackage.dll, appxreg.dll, cmifw.dll, edgeai.dll, eventsinstaller.dll, firewallofflineapi.dll, grouptrusteeai.dll, hotpatchai.dll, httpai.dll, implatsetup.dll, luainstall.dll, netfxconfig.dll, netsetupai.dll, netsetupapi.dll, netsetupengine.dll, perfcounterinstaller.dll, timezoneai.dll, winsockai.dll, wmicmiplugin.dll, ws2_helper.dll
x86_microsoft-windows-s..cingstack-onecoreds_31bf3856ad364e35 [10.0.22621.2567] -> offlinelsa.dll, offlinesam.dll
x86_microsoft-windows-s..ck-mof-onecoreadmin_31bf3856ad364e35 [10.0.22621.2567] -> esscli.dll, fastprox.dll, mofd.dll, mofinstall.dll, repdrvfs.dll, wbemcomn.dll, wbemcore.dll, wbemprox.dll, wmiutils.dll
x86_microsoft-windows-s..formers-shell-extra_31bf3856ad364e35 [10.0.22621.2567] -> shtransform.dll
x86_microsoft-windows-s..gstack-boot-onecore_31bf3856ad364e35 [10.0.22621.2567] -> bfsvc.dll, fveupdateai.dll, securebootai.dll
x86_microsoft-windows-s..k-transformers-core_31bf3856ad364e35 [10.0.22621.2567] -> primitivetransformers.dll
x86_microsoft-windows-s..llers-onecore-extra_31bf3856ad364e35 [10.0.22621.2567] -> bcdeditai.dll, configureieoptionalcomponentsai.dll, featuresettingsoverride.dll, iefileinstallai.dll, msdtcadvancedinstaller.dll, netfxconfig.dll, peerdistai.dll, printadvancedinstaller.dll, servicemodelregai.dll, setieinstalleddateai.dll, sppinst.dll
x86_microsoft-windows-s..ngstack-onecorebase_31bf3856ad364e35 [10.0.22621.2567] -> grouptrusteeai.dll
x86_microsoft-windows-s..or-native-serverbox_31bf3856ad364e35 [10.0.22621.2506] -> rmactivate_ssp.exe, secproc_ssp.dll
x86_microsoft-windows-s..ransformers-onecore_31bf3856ad364e35 [10.0.22621.2567] -> aritransformer.dll, wpndatatransformer.dll
x86_microsoft-windows-s..stack-termsrv-extra_31bf3856ad364e35 [10.0.22621.2567] -> appserverai.dll, rdwebai.dll, tssdisai.dll, vmhostai.dll
x86_microsoft-windows-security-spp-client_31bf3856ad364e35 [10.0.22621.2506] -> slc.dll, sppc.dll
x86_microsoft-windows-security-spp-pidgenx_31bf3856ad364e35 [10.0.22621.2506] -> pidgenx.dll
x86_microsoft-windows-servicingstack-inetsrv_31bf3856ad364e35 [10.0.22621.2567] -> iissetupai.dll
x86_microsoft-windows-servicingstack-onecore_31bf3856ad364e35 [10.0.22621.2567] -> cleanupai.dll
x86_microsoft-windows-servicingstack_31bf3856ad364e35 [10.0.22621.2567] -> cbscore.dll, cbsmsg.dll, dpx.dll, drupdate.dll, drvstore.dll, msdelta.dll, mspatcha.dll, poqexec.exe, reservemanager.dll, smiengine.dll, smipi.dll, tifilefetcher.exe, tiworker.exe, turbocontainer.dll, turbostack.dll, updateagent.dll, wcp.dll, wdscore.dll, wrpint.dll
x86_microsoft-windows-shell-comctl32-v5_31bf3856ad364e35 [10.0.22621.2506] -> comctl32.dll
x86_microsoft-windows-sxs_31bf3856ad364e35 [10.0.22621.2506] -> sxs.dll, sxsmigplugin.dll, sxstrace.exe
x86_microsoft-windows-t..-tsappsrv-component_31bf3856ad364e35 [10.0.22621.2506] -> tsmsiprxy.dll, tsmsisrv.dll, tsvip.sys, tsvipool.dll, tsvipsrv.dll
x86_microsoft.grouppolicy.admtmpleditor_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.grouppolicy.admtmpleditor.dll
x86_microsoft.grouppolicy.interop_31bf3856ad364e35 [10.0.22621.2506] -> microsoft.grouppolicy.interop.dll
x86_microsoft.windows.common-controls_6595b64144ccf1df [6.0.22621.2506] -> comctl32.dll
x86_microsoft.windows.gdiplus_6595b64144ccf1df [1.1.22621.2506] -> gdiplus.dll
```

</details>

---

## Methodology & Tools

This mapping was extracted using the [msrc-patch-pipeline](https://github.com/Chrono-Technology/msrc-patch-pipeline) automated Patch Tuesday analysis tool. The extraction process:

1. **Download** both the fix CU (KB5032190) and superseded CU (KB5031354) as `.msu` files from the Microsoft Update Catalog
2. **Extract** the inner CAB (legacy format) or WIM (modern format) containing component manifests
3. **Decompress** DCM-compressed manifests using the wcp.dll dictionary (Win32 resource type 614 #1) + `msdelta.dll ApplyDeltaB`
4. **Parse** each manifest XML for `<file>` elements to extract PE binary names and DigestValue hashes
5. **Diff** the two inventories by hash to identify changed, added, and removed binaries
6. **Map** component IDs from manifest filenames (format: `<arch>_<name>_<pubkey>_<version>_<locale>_<hash>.manifest`)

### Legacy vs Modern CU Format

| Feature | Legacy (pre-Win11 22H2) | Modern (Win11 22H2+) |
|---------|------------------------|---------------------|
| Manifest container | Inner CAB (~88MB) | WIM image |
| Delta patches | PSF (~494MB) | PSF |
| Manifest compression | DCM (PA30 deltas) | DCM (PA30 deltas) |
| Physical PEs in package | ~79 (servicing stack only) | None |
| Manifest count | ~23,830 | ~24,000+ |

Both formats use the same DCM compression and manifest XML schema. The only difference is the container format (CAB vs WIM) and that legacy CABs also include servicing stack PE binaries directly.

### WinSxS Component Store

On a running Windows system, these components are installed into `C:\Windows\WinSxS` as:

```
C:\Windows\WinSxS\<arch>_<name>_<pubkey>_<version>_<locale>_<hash>\
```

For example:
```
C:\Windows\WinSxS\amd64_microsoft-windows-ntfs_31bf3856ad364e35_10.0.22621.2715_none_abc123\
    ntfs.sys
```

This is how Windows maintains side-by-side component versions and enables rollback.

## Use Cases

- **Patch Tuesday analysis**: Given a CVE advisory that mentions a component name, look up which binaries need to be diffed
- **Attack surface mapping**: Identify all binaries in a specific subsystem (kernel, win32k, networking)
- **Binary provenance**: Determine which WinSxS component owns a given DLL or SYS file
- **Diff prioritization**: Components at version `.2715` have security fixes; `.2506` are routine version bumps

---

*Data extracted on 2026-03-10 from KB5032190 (November 2023 Patch Tuesday, Windows 11 22H2, build 10.0.22621.2715).*
