#include "pch.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <bitset>
#include <array>
#include <string>
#include <intrin.h>

class InstructionSet
{
    // forward declarations
    class InstructionSet_Internal;

public:
    // getters
    static std::string Vendor(void) { return CPU_Rep.vendor_; }
    static std::string Brand(void) { return CPU_Rep.brand_; }

    static bool SSE3(void) { return CPU_Rep.f_1_ECX_[0]; }
    static bool PCLMULQDQ(void) { return CPU_Rep.f_1_ECX_[1]; }
    static bool MONITOR(void) { return CPU_Rep.f_1_ECX_[3]; }
    static bool SSSE3(void) { return CPU_Rep.f_1_ECX_[9]; }
    static bool FMA(void) { return CPU_Rep.f_1_ECX_[12]; }
    static bool CMPXCHG16B(void) { return CPU_Rep.f_1_ECX_[13]; }
    static bool SSE41(void) { return CPU_Rep.f_1_ECX_[19]; }
    static bool SSE42(void) { return CPU_Rep.f_1_ECX_[20]; }
    static bool MOVBE(void) { return CPU_Rep.f_1_ECX_[22]; }
    static bool POPCNT(void) { return CPU_Rep.f_1_ECX_[23]; }
    static bool AES(void) { return CPU_Rep.f_1_ECX_[25]; }
    static bool XSAVE(void) { return CPU_Rep.f_1_ECX_[26]; }
    static bool OSXSAVE(void) { return CPU_Rep.f_1_ECX_[27]; }
    static bool AVX(void) { return CPU_Rep.f_1_ECX_[28]; }
    static bool F16C(void) { return CPU_Rep.f_1_ECX_[29]; }
    static bool RDRAND(void) { return CPU_Rep.f_1_ECX_[30]; }

    static bool MSR(void) { return CPU_Rep.f_1_EDX_[5]; }
    static bool CX8(void) { return CPU_Rep.f_1_EDX_[8]; }
    static bool SEP(void) { return CPU_Rep.f_1_EDX_[11]; }
    static bool CMOV(void) { return CPU_Rep.f_1_EDX_[15]; }
    static bool CLFSH(void) { return CPU_Rep.f_1_EDX_[19]; }
    static bool MMX(void) { return CPU_Rep.f_1_EDX_[23]; }
    static bool FXSR(void) { return CPU_Rep.f_1_EDX_[24]; }
    static bool SSE(void) { return CPU_Rep.f_1_EDX_[25]; }
    static bool SSE2(void) { return CPU_Rep.f_1_EDX_[26]; }

    static bool FSGSBASE(void) { return CPU_Rep.f_7_EBX_[0]; }
    static bool BMI1(void) { return CPU_Rep.f_7_EBX_[3]; }
    static bool HLE(void) { return CPU_Rep.isIntel_ && CPU_Rep.f_7_EBX_[4]; }
    static bool AVX2(void) { return CPU_Rep.f_7_EBX_[5]; }
    static bool BMI2(void) { return CPU_Rep.f_7_EBX_[8]; }
    static bool ERMS(void) { return CPU_Rep.f_7_EBX_[9]; }
    static bool INVPCID(void) { return CPU_Rep.f_7_EBX_[10]; }
    static bool RTM(void) { return CPU_Rep.isIntel_ && CPU_Rep.f_7_EBX_[11]; }
    static bool AVX512F(void) { return CPU_Rep.f_7_EBX_[16]; }
    static bool RDSEED(void) { return CPU_Rep.f_7_EBX_[18]; }
    static bool ADX(void) { return CPU_Rep.f_7_EBX_[19]; }
	static bool IPT(void) { return CPU_Rep.f_7_EBX_[25]; }
    static bool AVX512PF(void) { return CPU_Rep.f_7_EBX_[26]; }
    static bool AVX512ER(void) { return CPU_Rep.f_7_EBX_[27]; }
    static bool AVX512CD(void) { return CPU_Rep.f_7_EBX_[28]; }
    static bool SHA(void) { return CPU_Rep.f_7_EBX_[29]; }

    static bool PREFETCHWT1(void) { return CPU_Rep.f_7_ECX_[0]; }

    static bool LAHF(void) { return CPU_Rep.f_81_ECX_[0]; }
    static bool LZCNT(void) { return CPU_Rep.isIntel_ && CPU_Rep.f_81_ECX_[5]; }
    static bool ABM(void) { return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[5]; }
    static bool SSE4a(void) { return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[6]; }
    static bool XOP(void) { return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[11]; }
    static bool TBM(void) { return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[21]; }

    static bool SYSCALL(void) { return CPU_Rep.isIntel_ && CPU_Rep.f_81_EDX_[11]; }
    static bool MMXEXT(void) { return CPU_Rep.isAMD_ && CPU_Rep.f_81_EDX_[22]; }
    static bool RDTSCP(void) { return CPU_Rep.isIntel_ && CPU_Rep.f_81_EDX_[27]; }
    static bool _3DNOWEXT(void) { return CPU_Rep.isAMD_ && CPU_Rep.f_81_EDX_[30]; }
    static bool _3DNOW(void) { return CPU_Rep.isAMD_ && CPU_Rep.f_81_EDX_[31]; }

private:
    static const InstructionSet_Internal CPU_Rep;

    class InstructionSet_Internal
    {
    public:
        InstructionSet_Internal()
            : nIds_{ 0 },
            nExIds_{ 0 },
            isIntel_{ false },
            isAMD_{ false },
			Stepping{ 0 },
			Model{ 0 },
			Family{ 0 },
			BrandIndex{ 0 },
			CflushLineSize{ 0 },
			MaxAddrID{ 0 },
			InitAPICID{ 0 },
			isCR3{ false },
			isPSBAndCAM{ false },
			isADDRCFG{ false },
			isMTC{ false },
			isTOPA{ false },
			isTOPAMul{ false },
			isSingle{ false },
			isLIP{ false },
			addr_range{ 0 },
			mtc_freq_mask{ 0 },
			cyc_thresh_mask{ 0 },
			psb_freq_mask{ 0 },
			bus_freq{ 0.0 },
			f_1_EAX_{ 0 },
			f_1_EBX_{ 0 },
            f_1_ECX_{ 0 },
            f_1_EDX_{ 0 },
            f_7_EBX_{ 0 },
            f_7_ECX_{ 0 },
			f_14_EBX_{ 0 },
			f_14_ECX_{ 0 },
			f_141_EAX_{ 0 },
			f_141_EBX_{ 0 },
			f_15_EAX_{ 0 },
			f_15_EBX_{ 0 },
            f_81_ECX_{ 0 },
            f_81_EDX_{ 0 },
            data_{},
            extdata_{}
        {
            //int cpui[4] = {-1};
            std::array<int, 4> cpui;

            // Calling __cpuid with 0x0 as the function_id argument
            // gets the number of the highest valid function ID.
            __cpuid(cpui.data(), 0);
            nIds_ = cpui[0];

            for (int i = 0; i <= nIds_; ++i)
            {
                __cpuidex(cpui.data(), i, 0);
                data_.push_back(cpui);
				std::cout << "cpuid[" << std::hex << std::setw(8) << std::setfill('0') << i 
					<< "][0] a=" << std::hex << std::setw(8) << std::setfill('0') << cpui[0] 
					<< " b=" << std::hex << std::setw(8) << std::setfill('0') << cpui[1] 
					<< " c=" << std::hex << std::setw(8) << std::setfill('0') << cpui[2] 
					<< " d=" << std::hex << std::setw(8) << std::setfill('0') << cpui[3] << std::endl;
            }

            // Capture vendor string
            char vendor[0x20];
            memset(vendor, 0, sizeof(vendor));
            *reinterpret_cast<int*>(vendor) = data_[0][1];
            *reinterpret_cast<int*>(vendor + 4) = data_[0][3];
            *reinterpret_cast<int*>(vendor + 8) = data_[0][2];
            vendor_ = vendor;
            if (vendor_ == "GenuineIntel")
            {
                isIntel_ = true;
            }
            else if (vendor_ == "AuthenticAMD")
            {
                isAMD_ = true;
            }

            // load bitset with flags for function 0x00000001
            if (nIds_ >= 1)
            {
				f_1_EAX_ = data_[1][0];
				f_1_EBX_ = data_[1][1];
				f_1_ECX_ = data_[1][2];
				f_1_EDX_ = data_[1][3];

				Stepping = f_1_EAX_ & 0xf;
				Model = (f_1_EAX_ >> 4) & 0xf;
				Family = (f_1_EAX_ >> 8) & 0xf;
				if (Family == 6 || Family == 0xf)
					Model += ((f_1_EAX_ >> 16) & 0xf) << 4;
				if (Family == 0xf)
					Family += (f_1_EAX_ >> 20) & 0xff;

				BrandIndex = f_1_EBX_ & 0xff;
				CflushLineSize = (f_1_EBX_ >> 8) & 0xff;
				MaxAddrID = (f_1_EBX_ >> 16) & 0xff;
				InitAPICID = (f_1_EBX_ >> 24) & 0xff;                

				std::cout << "Stepping=0x" << std::hex << std::setw(2) << std::setfill('0') << Stepping << std::endl;
				std::cout << "Model=0x" << std::hex << std::setw(8) << std::setfill('0') << Model << std::endl;
				std::cout << "Family=0x" << std::hex << std::setw(8) << std::setfill('0') << Family << std::endl;
				std::cout << "BrandIndex=0x" << std::hex << std::setw(2) << std::setfill('0') << BrandIndex << std::endl;
				std::cout << "CflushLineSize=0x" << std::hex << std::setw(2) << std::setfill('0') << CflushLineSize << std::endl;
				std::cout << "MaxAddrID=0x" << std::hex << std::setw(2) << std::setfill('0') << MaxAddrID << std::endl;
				std::cout << "InitAPICID=0x" << std::hex << std::setw(2) << std::setfill('0') << InitAPICID << std::endl;
            }

            // load bitset with flags for function 0x00000007
            if (nIds_ >= 7)
            {
                f_7_EBX_ = data_[7][1];
                f_7_ECX_ = data_[7][2];
            }

			// load bitset with flags for function 0x000000014
			if (nIds_ >= 0x14)
			{
				f_14_EBX_ = data_[0x14][1];
				f_14_ECX_ = data_[0x14][2];

				if (f_14_EBX_[0]) {
					isCR3 = true;
				}
				if (f_14_EBX_[1]) {
					isPSBAndCAM = true;
				}
				if (f_14_EBX_[2]) {
					isADDRCFG = true;
				}
				if (f_14_EBX_[3]) {
					isMTC = true;
				}

				if (f_14_ECX_[0]) {
					isTOPA = true;
				}
				if (f_14_ECX_[1]) {
					isTOPAMul = true;
				}
				if (f_14_ECX_[2]) {
					isSingle = true;
				}
				if (f_14_EBX_[31]) {
					isLIP = true;
				}

				std::cout << "isCR3=" << isCR3 << std::endl;
				std::cout << "isPSBAndCAM=" << isPSBAndCAM << std::endl;
				std::cout << "isADDRCFG=" << isADDRCFG << std::endl;
				std::cout << "isMTC=" << isMTC << std::endl;
				std::cout << "isTOPA=" << isTOPA << std::endl;
				std::cout << "isTOPAMul=" << isTOPAMul << std::endl;
				std::cout << "isSingle=" << isSingle << std::endl;
				std::cout << "isLIP=" << isLIP << std::endl;

				if (isPSBAndCAM && isMTC && data_[0x14][0] >= 1) {
					__cpuidex(cpui.data(), 0x14, 1);
					data_.push_back(cpui);
					std::cout << "cpuid[00000014][1] a=" << std::hex << std::setw(8) << std::setfill('0') << cpui[0]
						<< " b=" << std::hex << std::setw(8) << std::setfill('0') << cpui[1]
						<< " c=" << std::hex << std::setw(8) << std::setfill('0') << cpui[2]
						<< " d=" << std::hex << std::setw(8) << std::setfill('0') << cpui[3] << std::endl;

					f_141_EAX_ = cpui[0];
					f_141_EBX_ = cpui[1];
					addr_range = f_141_EAX_ & 0x3;
					mtc_freq_mask = (f_141_EAX_ >> 16) & 0xffff;
					cyc_thresh_mask = f_141_EBX_ & 0xffff;
					psb_freq_mask = (f_141_EBX_ >> 16) & 0xffff;

					std::cout << "addr_range=0x" << std::hex << std::setw(2) << std::setfill('0') << addr_range << std::endl;
					std::cout << "mtc_freq_mask=0x" << std::hex << std::setw(2) << std::setfill('0') << mtc_freq_mask << std::endl;
					std::cout << "cyc_thresh_mask=0x" << std::hex << std::setw(2) << std::setfill('0') << cyc_thresh_mask << std::endl;
					std::cout << "psb_freq_mask=0x" << std::hex << std::setw(2) << std::setfill('0') << psb_freq_mask << std::endl;
				}
			}

			// load bitset with flags for function 0x000000015
			if (nIds_ >= 0x15)
			{
				f_15_EAX_ = data_[0x15][0];
				f_15_EBX_ = data_[0x15][1];

				if (f_15_EAX_ && f_15_EBX_)
					bus_freq = (float)1.0 / ((float)f_15_EAX_ / (float)f_15_EBX_);

				std::cout << "bus_freq=" << std::setprecision(8) << bus_freq << std::endl;
			}

            // Calling __cpuid with 0x80000000 as the function_id argument
            // gets the number of the highest valid extended ID.
            __cpuid(cpui.data(), 0x80000000);
            nExIds_ = cpui[0];

            char brand[0x40];
            memset(brand, 0, sizeof(brand));

            for (int i = 0x80000000; i <= nExIds_; ++i)
            {
                __cpuidex(cpui.data(), i, 0);
                extdata_.push_back(cpui);
				std::cout << "cpuid[" << std::hex << std::setw(8) << std::setfill('0') << i 
					<< "][0] a=" << std::hex << std::setw(8) << std::setfill('0') << cpui[0] 
					<< " b=" << std::hex << std::setw(8) << std::setfill('0') << cpui[1] 
					<< " c=" << std::hex << std::setw(8) << std::setfill('0') << cpui[2] 
					<< " d=" << std::hex << std::setw(8) << std::setfill('0') << cpui[3] << std::endl;
            }

            // load bitset with flags for function 0x80000001
            if (nExIds_ >= 0x80000001)
            {
                f_81_ECX_ = extdata_[1][2];
                f_81_EDX_ = extdata_[1][3];
            }

            // Interpret CPU brand string if reported
            if (nExIds_ >= 0x80000004)
            {
                memcpy(brand, extdata_[2].data(), sizeof(cpui));
                memcpy(brand + 16, extdata_[3].data(), sizeof(cpui));
                memcpy(brand + 32, extdata_[4].data(), sizeof(cpui));
                brand_ = brand;
            }
        };

        int nIds_;
        int nExIds_;
        std::string vendor_;
        std::string brand_;
        bool isIntel_;
        bool isAMD_;
		unsigned int Stepping;
		unsigned int Model;
		unsigned int Family;
		unsigned int BrandIndex;
		unsigned int CflushLineSize;
		unsigned int MaxAddrID;
		unsigned int InitAPICID;
		bool isCR3;
		bool isPSBAndCAM;
		bool isADDRCFG;
		bool isMTC;
		bool isTOPA;
		bool isTOPAMul;
		bool isSingle;
		bool isLIP;
		unsigned short addr_range;
		unsigned short mtc_freq_mask;
		unsigned short cyc_thresh_mask;
		unsigned short psb_freq_mask;
		float bus_freq;
		unsigned int  f_1_EAX_;
		unsigned int  f_1_EBX_;
        std::bitset<32> f_1_ECX_;
        std::bitset<32> f_1_EDX_;
        std::bitset<32> f_7_EBX_;
        std::bitset<32> f_7_ECX_;
		std::bitset<32> f_14_EBX_;
		std::bitset<32> 	f_14_ECX_;
		unsigned int  f_141_EAX_;
		unsigned int  f_141_EBX_;
		unsigned int  f_15_EAX_;
		unsigned int  f_15_EBX_;
        std::bitset<32> f_81_ECX_;
        std::bitset<32> f_81_EDX_;
        std::vector<std::array<int, 4>> data_;
        std::vector<std::array<int, 4>> extdata_;
    };
};

// Initialize static member data
const InstructionSet::InstructionSet_Internal InstructionSet::CPU_Rep;

// Print out supported instruction set extensions
int main(int argc, char * argv[])
{
    auto& outstream = std::cout;

    auto support_message = [&outstream](std::string isa_feature, bool is_supported) {
        outstream << isa_feature << (is_supported ? " supported" : " not supported") << std::endl;
    };

    std::cout << InstructionSet::Vendor() << std::endl;
    std::cout << InstructionSet::Brand() << std::endl;

    support_message("3DNOW",       InstructionSet::_3DNOW());
    support_message("3DNOWEXT",    InstructionSet::_3DNOWEXT());
    support_message("ABM",         InstructionSet::ABM());
    support_message("ADX",         InstructionSet::ADX());
    support_message("AES",         InstructionSet::AES());
    support_message("AVX",         InstructionSet::AVX());
    support_message("AVX2",        InstructionSet::AVX2());
    support_message("AVX512CD",    InstructionSet::AVX512CD());
    support_message("AVX512ER",    InstructionSet::AVX512ER());
    support_message("AVX512F",     InstructionSet::AVX512F());
    support_message("AVX512PF",    InstructionSet::AVX512PF());
	support_message("IPT", InstructionSet::IPT());
    support_message("BMI1",        InstructionSet::BMI1());
    support_message("BMI2",        InstructionSet::BMI2());
    support_message("CLFSH",       InstructionSet::CLFSH());
    support_message("CMPXCHG16B",  InstructionSet::CMPXCHG16B());
    support_message("CX8",         InstructionSet::CX8());
    support_message("ERMS",        InstructionSet::ERMS());
    support_message("F16C",        InstructionSet::F16C());
    support_message("FMA",         InstructionSet::FMA());
    support_message("FSGSBASE",    InstructionSet::FSGSBASE());
    support_message("FXSR",        InstructionSet::FXSR());
    support_message("HLE",         InstructionSet::HLE());
    support_message("INVPCID",     InstructionSet::INVPCID());
    support_message("LAHF",        InstructionSet::LAHF());
    support_message("LZCNT",       InstructionSet::LZCNT());
    support_message("MMX",         InstructionSet::MMX());
    support_message("MMXEXT",      InstructionSet::MMXEXT());
    support_message("MONITOR",     InstructionSet::MONITOR());
    support_message("MOVBE",       InstructionSet::MOVBE());
    support_message("MSR",         InstructionSet::MSR());
    support_message("OSXSAVE",     InstructionSet::OSXSAVE());
    support_message("PCLMULQDQ",   InstructionSet::PCLMULQDQ());
    support_message("POPCNT",      InstructionSet::POPCNT());
    support_message("PREFETCHWT1", InstructionSet::PREFETCHWT1());
    support_message("RDRAND",      InstructionSet::RDRAND());
    support_message("RDSEED",      InstructionSet::RDSEED());
    support_message("RDTSCP",      InstructionSet::RDTSCP());
    support_message("RTM",         InstructionSet::RTM());
    support_message("SEP",         InstructionSet::SEP());
    support_message("SHA",         InstructionSet::SHA());
    support_message("SSE",         InstructionSet::SSE());
    support_message("SSE2",        InstructionSet::SSE2());
    support_message("SSE3",        InstructionSet::SSE3());
    support_message("SSE4.1",      InstructionSet::SSE41());
    support_message("SSE4.2",      InstructionSet::SSE42());
    support_message("SSE4a",       InstructionSet::SSE4a());
    support_message("SSSE3",       InstructionSet::SSSE3());
    support_message("SYSCALL",     InstructionSet::SYSCALL());
    support_message("TBM",         InstructionSet::TBM());
    support_message("XOP",         InstructionSet::XOP());
    support_message("XSAVE",       InstructionSet::XSAVE());
	
    return 0;
}
