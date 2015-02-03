#ifndef KRIPPTX_H
#define KRIPPTX_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>

#define DUCP_SIZE		        256
#define DUCP_NOTSET		        -1

#define DUCP_VALUENOTUSED	    0
#define DUCP_VALUEUSED		    1

#define DUCP_STATE_NOTCONNECTED	0
#define DUCP_STATE_CONNECTED	1

namespace Kripptx
{
	typedef unsigned char byte;
	typedef unsigned long ulong;

	class Kripptx
	{
	private:
		byte State;						//Main state: DUCP_STATE_NOTCONNECTED, DUCP_STATE_CONNECTED etc.
		short DUCP[DUCP_SIZE];			//Main memory encription key
		ulong DucpVersion;			    //How many times DUCP have been changed
		byte UsedValuesMap[DUCP_SIZE];	//Map of used values in DUCP (DUCP_VALUENOTUSED, DUCP_VALUEUSED)
		short FilledCells;				//Count of correctly filled cells in DUCP
		short DucpOne;					//Swap
		short DucpAll[DUCP_SIZE];		//Swap array AND reverse array
		byte RoundCount;				//How many rounds of encryption of a message to do
		float ProbToGenKey;				//Probability to generate a Key (but not a Value) to next round
		float ProbDecay;				//Probability decay rate
		short Key;						//Last Key
		short Value;					//Last Value
		short ToSend;					//Key or Value to Send
		char DucpString[DUCP_SIZE * 6];	//Stringed version of DUCP (will assemble by request)
	    int ExtraRand;                  //Extra randomization variable
	    char LogFileName[256];          //If set, logs out all activity
	    bool isLogging;                 //To log or not to log?

	public:
		///////////////////////////////////////////////////////////////////////////////
		//
		//	Init and configure
		//
		///////////////////////////////////////////////////////////////////////////////
		Kripptx(void)
		{
		    isLogging = false;
		    ProbDecay = 2.0;
		    RoundCount = 16;
			Reset();
		}

		void SetLogging(const char* FileName)
		{
		    strcpy(LogFileName, FileName);
		    isLogging = true;
		}

		//Sets (default) encription/decryption's round count. Must be equal on both peers. Must be setted up before exchange process begins.
		bool SetRoundsCount(byte iRoundCount)
		{
			if(State == DUCP_STATE_NOTCONNECTED)
			{
				RoundCount = iRoundCount;
				return true;
			}
			return false;
		}

		//Sets (default) decay of pointer selection probability. Must be equal on both peers. Must be setted up before exchange process begins.
		bool SetProbDecay(float fProbDecay)
		{
			if(State == DUCP_STATE_NOTCONNECTED)
			{
				ProbDecay = fProbDecay;
				return true;
			}
			return false;
		}

        //Simulates an primitive (unsafe) connection
		void SimulateConnection(void)
		{
		    State = DUCP_STATE_CONNECTED;
			for(short c = 0; c < DUCP_SIZE; c++)
			{
			    //As 11 and 255 is coprime integers, so 11 is Generator over the Field of [0, 255]
				DUCP[(11 * c) % DUCP_SIZE] = c;
				UsedValuesMap[c] = DUCP_VALUEUSED;
			}
			FilledCells = DUCP_SIZE;
			DucpVersion = DUCP_SIZE + 1;
			GetDUCP();
		}

		//Gets stringed version of DUCP (for debug purposes, for ex.)
		const char* GetDUCP(void)
		{
			char ValTmp[8];
			memset(DucpString, 0, DUCP_SIZE * 6 * sizeof(char));
			for(short c = 0; c < DUCP_SIZE; c++)
			{
                if(DUCP[c] == DUCP_NOTSET)
                    sprintf(ValTmp, (c ? " _": "_"));
                else
                    sprintf(ValTmp, (c ? " %i": "%i"), DUCP[c]);
				strcat(DucpString, ValTmp);
			}
			return static_cast<const char*>(DucpString);
		}

		///////////////////////////////////////////////////////////////////////////////
		//
		//	Encryption
		//
		///////////////////////////////////////////////////////////////////////////////

		//Encrypts message Message of length Length and stores it right there (in Message)
		void sE(const ulong Length, byte* Message) const
		{
			if(Length && Message && (State == DUCP_STATE_CONNECTED))
			{
				ulong p, Offset;

				for(int r = 0; r < RoundCount; r++)
				{
					Offset = 1;
					for(p = 0; p < Length; p++)
					{
						//1. Inverting
						Message[p] = (DUCP_SIZE-1) - Message[p];

						//2. Sum with DUCP
						Message[p] = (Message[p] + DUCP[p % DUCP_SIZE]) % DUCP_SIZE;

						//3. Applying DUCP
						Message[p] = DUCP[Message[p] % DUCP_SIZE];

						//4.1. Preparing to shift
						Offset += Message[p];
					}

					//4.2. Shifting
					if(Offset)
					{
						Shift(Message, Length, Offset);
					}
				}
			}
		}

		///////////////////////////////////////////////////////////////////////////////
		//
		//	Decryption
		//
		///////////////////////////////////////////////////////////////////////////////

		//Decrypts message Message of length Length and stores it right there (in Message)
		void sD(const ulong Length, byte* Message)
		{
			if(Length && Message && (State == DUCP_STATE_CONNECTED))
			{
				ulong p, Offset;

				//Preparing reverse DUCP
				for(short c = 0; c < DUCP_SIZE; c++)
				{
				    if((0 <= DUCP[c]) && (DUCP[c] < DUCP_SIZE))
					DucpAll[DUCP[c]] = c;
				}

				for(int r = 0; r < RoundCount; r++)
				{
					//1.1. Preparing to unshift
					Offset = 1;
					for(p = 0; p < Length; p++)
						Offset += Message[p];

					//1.2. Unshifting
					if(Offset)
					{
						Shift(Message, Length, -Offset);
					}

					for(p = 0; p < Length; p++)
					{
						//2. Unapplying DUCP
						Message[p] = DucpAll[Message[p] % DUCP_SIZE];

						//3. Unsum with DUCP
						Message[p] = (Message[p] + DUCP_SIZE - DUCP[p % DUCP_SIZE]) % DUCP_SIZE;

						//4. Uninverting
						Message[p] = (DUCP_SIZE-1) - Message[p];
					}
				}
			}
		}

		///////////////////////////////////////////////////////////////////////////////
		//
		//	Connection
		//
		///////////////////////////////////////////////////////////////////////////////

		//While connecting, generates either Key or Value (depends on current Probability) and stores it
		// as (Key = <some_number>, Value = DUCP_NOTSET) for Key
		// as (Key = DUCP_NOTSET, Value = <some_number>) for Value
		//This <some_number> should be sended to other side.
		void GenKV(void)
		{
			if(State == DUCP_STATE_NOTCONNECTED)
			{
				bool Connected = false;
				if(Random() < ProbToGenKey)
				{
					//Gen a Key, listen for a Value. We have to select a random unused Key
					int RandomKey = PickRandomElementFromArrayByFilterEQ(DUCP, DUCP_SIZE, DUCP_NOTSET);
					if(RandomKey != -1)
					{
						Key = RandomKey;
						ToSend = Key;
						ToLog("%s -> {%i _}\n", GetDUCP(), ToSend);
					}
					else
					{
						Key = DUCP_NOTSET;
						//There is no empty keys! Connected?
						Connected = true;
					}
					Value = DUCP_NOTSET;
				}
				else
				{
					//Gen a Value, listen for a Key. We have to select a random unused Value
					int RandomValue = PickRandomElementFromArrayByFilterEQ(UsedValuesMap, DUCP_SIZE, DUCP_VALUENOTUSED);
					if(RandomValue != -1)
					{
						Value = RandomValue;
						ToSend = Value;
						ToLog("%s -> {_ %i}\n", GetDUCP(), ToSend);
					}
					else
					{
						Value = DUCP_NOTSET;
						//There is no empty values! Connected?
						Connected = true;
					}
					Key = DUCP_NOTSET;
				}

				if(Connected)
				{
					//well done!
					State = DUCP_STATE_CONNECTED;
					ToSend = DUCP_NOTSET;
					ToLog("%s Connected!\n", GetDUCP());
				}
			}
		}

		//Returns last Key_or_Value, may return DUCP_NOTSET
		short GetKV(void) const
		{
			return ToSend;
		}

		//While connecting, recieves this <some_number> from other side and process it in DUCP construction
		void ProcessKV(const short KV)
		{
			if(State == DUCP_STATE_NOTCONNECTED)
			{
                ToLog("Incoming {%i}\n", KV);

				if(KV == DUCP_NOTSET)
				{
					//there is an error on that side. reset all!
					Reset();
					return;
				}

				bool KeyThisTime = false;

				if(Value == DUCP_NOTSET)
				{
					Value = KV;
					KeyThisTime = true;
				}
				if(Key == DUCP_NOTSET)
				{
					Key = KV;
					KeyThisTime = false;
				}

			    ToLog("%s + {%i %i} = ", GetDUCP(), Key, Value);

				//check for conflict
				if((DUCP[Key] == DUCP_NOTSET) && (UsedValuesMap[Value] == DUCP_VALUENOTUSED))
				{
					//ok: apply all
					DUCP[Key] = Value;
					UsedValuesMap[Value] = DUCP_VALUEUSED;
					FilledCells++;

					//affect to probability
					if(KeyThisTime)
					{
						ProbToGenKey = ProbToGenKey / (ProbDecay + static_cast<float>(Value % 2));
					}
					else
					{
						ProbToGenKey = 1.0 - ((1.0 - ProbToGenKey) / (ProbDecay + static_cast<float>(Value % 2)));
					}

					ToLog("%s\nFilled Cells: %i, Key Probability: %f\n", GetDUCP(), FilledCells, ProbToGenKey);
				}
				else
				{
					//conflict: reset all
					ToLog("Collision!\n");
					Reset();
				}
			}
		}

		//Tests a class
		int Test(void)   //runs all tests
		{
		    int TestResult = TestAll();
		    ToLog("Test Result: %i\n", TestResult);
		    return TestResult;
		}


	private:
		///////////////////////////////////////////////////////////////////////////////
		//
		//	Deleted functions
		//
		///////////////////////////////////////////////////////////////////////////////
		Kripptx(const Kripptx& rhs);		//copy constructor is private and empty! This is for preventing to use such code as {Kripptx Kripptx1; Kripptx Kripptx2(Kripptx1);}
		Kripptx& operator=(const Kripptx& rhs);	//assignment operator is private and empty! This is for preventing to use such code as {Kripptx Kripptx1, Kripptx2; Kripptx2 = Kripptx1;}
						//default constructor is exist
						//default destructor is created by compiler

		///////////////////////////////////////////////////////////////////////////////
		//
		//	Init and configure
		//
		///////////////////////////////////////////////////////////////////////////////

		//Sets all default parameters
		void Reset(void)
		{
			srand(time(NULL) + ExtraRand);
			ExtraRand += Random(333, 777);
			ToLog("Resetting!\n");

			for(short c = 0; c < DUCP_SIZE; c++)
			{
				DUCP[c] = DUCP_NOTSET;
				DucpAll[c] = DUCP_NOTSET;
				UsedValuesMap[c] = DUCP_VALUENOTUSED;
			}
			FilledCells = 0;

			State = DUCP_STATE_NOTCONNECTED;

			DucpVersion = 0;

			ProbToGenKey = 0.5;

			Key = DUCP_NOTSET;
			Value = DUCP_NOTSET;
			ToSend = DUCP_NOTSET;
		}

		///////////////////////////////////////////////////////////////////////////////
		//
		//	Changing DUCP
		//
		///////////////////////////////////////////////////////////////////////////////
		void DeltaAB(const byte A, const byte B)
		{
			if(A != B)
			{
				DucpOne = DUCP[A];
				DUCP[A] = DUCP[B];
				DUCP[B] = DucpOne;
			}
		}

		void DeltaM(const byte M)
		{
			Shift(DUCP, DUCP_SIZE, M);
		}

		void Delta(void)
		{
			for(short c = 0; c < DUCP_SIZE; c++)
			{
			    if((0 <= DUCP[c]) && (DUCP[c] < DUCP_SIZE))
                {
                    DucpAll[c] = DUCP[DUCP[c]];
                }
			}
			memcpy(DUCP, DucpAll, DUCP_SIZE * sizeof(short));
		}

		void Omega(const byte A, const byte B, const byte M)
		{
			DeltaAB(A, B);
			DeltaM(M);
			Delta();
		}

		//Changes (with Omega and Delta hash functions) DUCP according to sended/recieved message Message.
		void sS(const ulong Length, const byte* Message)
		{
			if(Length && Message)
			{
				byte i, j;
				for(i = 0; i < 64; i++)
				{
					for(j = i + 1; j < 128; j++)
					{
						Omega(j, (j * j * j) % DUCP_SIZE, Message[i % Length]);
						Omega(DUCP_SIZE-1 - j, (j * j) % DUCP_SIZE, Message[Length / 2]);
						Omega(Message[i % Length], Message[j % Length], (i + j) % DUCP_SIZE);
					}
				}
				DucpVersion++;
			}
		}

		///////////////////////////////////////////////////////////////////////////////
		//
		//	Utils
		//
		///////////////////////////////////////////////////////////////////////////////

		//Right shifts an array Data of length Length to offset Offset
		template<typename T>
		void Shift(T* Data, const ulong& Length, long Offset) const
		{
            if((!Data) || (!Length))
                return;

            if(Offset < 0)
                Offset = (Length-1) - ((-Offset-1) % Length);
            else
                Offset %= Length;

            if(!Offset)
                return;

            int TSize = sizeof(T);

			T* Shifter = new T[Length];

			if(Shifter)
            {
                memcpy(Shifter, Data + Offset, TSize * (Length - Offset));
                memcpy(Shifter + (Length - Offset), Data, TSize * Offset);
                memcpy(Data, Shifter, TSize * Length);

                delete[] Shifter;
            }
		}

		//Picks a random element from array Data of length DataLength, which mathces criteria: Data[element] == Filter
		// and returns an Index of this element
		// or -1 if there are no such element
		template<typename T1, typename T2>
		int PickRandomElementFromArrayByFilterEQ(const T1* Data, const int DataLength, const T2 Filter) const
		{
			int RandomPointer = Random(0, DataLength - 1);
			int EndPoint = RandomPointer;
			while(true)
			{
				if(Data[RandomPointer] == Filter)
					return RandomPointer;
				RandomPointer = (RandomPointer + 1) % DataLength;
				if(RandomPointer == EndPoint)
					break;
			}
			return -1;
		}

		//Returns a random float in [0.0, 1.0]
		float Random(void) const
		{
			return (rand() % 32768) / 32767.0;
		}

		//Returns a random int in [A, B]
		const int Random(const int A, const int B) const
		{
			return A + Random() * (float)(B - A);
		}

		byte GetState(void) const
		{
			return State;
		}

		ulong GetDucpVersion() const
		{
			return DucpVersion;
		}

		void ToLog(const char* Format, ...) const
		{
            if(isLogging)
            {
                FILE* LogFile = fopen(LogFileName, "a+");
                if(LogFile)
                {
                    va_list args;
                    va_start(args, Format);
                    vfprintf(LogFile, Format, args);
                    va_end(args);

                    fflush(LogFile);
                    fclose(LogFile);
                }
            }
		}

		///////////////////////////////////////////////////////////////////////////////
		//
		//	Tests
		//
		///////////////////////////////////////////////////////////////////////////////

		//Tests a class
		int TestAll(void)   //tests all tests
		{
            if(!TestEstCon()) return -1;
            if(!TestExch()) return -2;
		    return 0;
		}

		bool TestEstCon(void)   //tests connection establishing (same DUCPs for both peers)
		{
			int SameDUCPCount = 0;
			int NotSameDUCPCount = 0;

			for(int iTest = 0; iTest < 100; iTest++)    //we'll simulate a connection establishing for 100 times
            {
                Kripptx KripptxAlice;
                Kripptx KripptxBob;

                KripptxAlice.SetProbDecay(1000);            //(such high probability is completely unsafe for public DUCP exchange!)
                KripptxBob.SetProbDecay(1000);              //(it is so high for test purposes only!)

                while((KripptxAlice.GetState() == DUCP_STATE_NOTCONNECTED) || (KripptxBob.GetState() == DUCP_STATE_NOTCONNECTED))
                {
                    KripptxAlice.GenKV();
                    KripptxBob.GenKV();
                    KripptxAlice.ProcessKV(KripptxBob.GetKV());
                    KripptxBob.ProcessKV(KripptxAlice.GetKV());
                }

                if(strcmp(KripptxAlice.GetDUCP(), KripptxBob.GetDUCP()) == 0)
                    SameDUCPCount++;
                else
                    NotSameDUCPCount++;
            }
            return (SameDUCPCount * 2 > NotSameDUCPCount);
		}

		bool TestExch(void)
		{
			bool bTestIsOK = true;

            Kripptx KripptxAlice;
            Kripptx KripptxBob;

            KripptxAlice.SetRoundsCount(8);
            KripptxBob.SetRoundsCount(8);
            KripptxAlice.SimulateConnection();
            KripptxBob.SimulateConnection();

            if(isLogging)
            {
                KripptxAlice.SetLogging("./AliceLog.txt");
                KripptxBob.SetLogging("./BobLog.txt");
            }

			ulong uMessageLen;
			byte* pbOriginalMessage;
			byte* pbMessage;
			Kripptx* pKripptxSender;
			Kripptx* pKripptxReciever;
			for(int iTest = 0; iTest < 100; iTest++)  //peers will exchange thier data for 100 times
			{
				//sender composes some new message (or data) of length uMessageLen and stores it in pbMessage
				uMessageLen = Random(100, 200);
				pbMessage = new byte[uMessageLen];
				if(pbMessage)
                {
                    memset(pbMessage, 0, uMessageLen * sizeof(byte));
                    for(ulong uChar = 0; uChar < uMessageLen; uChar++)
                        pbMessage[uChar] = Random(0, DUCP_SIZE - 1);

                    //encrypt function will change (encode) original pbMessage array,
                    // so for further purposes we have to copy original message from pbMessage to pbOriginalMessage
                    pbOriginalMessage = new byte[uMessageLen];
                    if(pbOriginalMessage)
                    {
                        memcpy(pbOriginalMessage, pbMessage, uMessageLen * sizeof(byte));

                        //assigning random sender and reciever
                        if(Random() < .5)
                        {
                            pKripptxSender = &KripptxAlice;
                            pKripptxReciever = &KripptxBob;
                        }
                        else
                        {
                            pKripptxReciever = &KripptxAlice;
                            pKripptxSender = &KripptxBob;
                        }

                        //------------------------------------------------------------------------------------
                        //Here both sender and reciever DUCP's versions are the same (say, v.N)

                        //sender encodes his message with DUCP (v.N) (so pbMessage array changes)
                        pKripptxSender->sE(uMessageLen, pbMessage);

                        //sender changes his DUCP (from v.N to v.N+1) using ORIGINAL message
                        pKripptxSender->sS(uMessageLen, pbOriginalMessage);

                        //sender sends his encoded message pbMessage to reciever (over the Net)

                        //reciever decodes encoded message with his DUCP (v.N)
                        pKripptxReciever->sD(uMessageLen, pbMessage);

                        //reciever changes his DUCP (from v.N to v.N+1) using ORIGINAL (same as encoded) message
                        pKripptxReciever->sS(uMessageLen, pbMessage);

                        //Now DUCP versions of both sender and reciever are the same (v.N+1)
                        //------------------------------------------------------------------------------------

                        //let's compare original message pbOriginalMessage and encoded/sended/recieved/decoded message pbMessage
                        if(memcmp(pbOriginalMessage, pbMessage, uMessageLen * sizeof(byte)))
                            bTestIsOK = false;

                        //clean up
                        delete [] pbOriginalMessage;
                        delete [] pbMessage;

                        //check if some error ocured...
                        if(!bTestIsOK)
                            return false;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    return false;
                }
			}
			return true;
		}
	};
}

#endif
