---
title: "Some Interview Questions I've Been Asked"
date: 2023-04-25T00:46:30-04:00 
categories:
  - Professional-Resources
header:
  teaser: /assets/images/Professional-Resources/Interview.png
tags:
  - Jobs
  - Interview
  
---

![Interview Logo](/assets/images/Professional-Resources/Interview.png)  

---

---  

### What is the main difference between x64 and ARM? (while discussing buffer overflows and instruction codes)


One of the main differences lies in how computing instructions are executed. x64 and x86 utilize **CISC**, or a **Complex Instruction Set Computer**, while ARM utilizes **RISC**, or a **Reduced Instruction Set Computer**. CISC is able to process more complex instructions in a single compute, while RISC utilizes multiple, smaller computations to achieve the same result. This results in more lines of assembly level instructions for RISC and requires more RAM.  


**Example:**  
Imagine you want to multiply two numbers and they are stored at registers 1300 and 1301. For CISC, it is easy. The machine performs a single MUL instruction on two registers, each being a number it is multiplying.  

```bash
CISC Instructions:
MUL 1300, 1301
```  


For RISC, however, the instruction set is going to be longer. It performs 3 additional actions, because it must load the first register, then load the second register. Then it can perform muliplication, and finally it stores the new value to memory.  


```bash
RISC Instructions:
Load A, 1300
Load B, 1301
Mul A, B
Store 1300, A
```  

---  

