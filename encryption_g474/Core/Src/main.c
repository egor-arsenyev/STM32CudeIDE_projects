/* USER CODE BEGIN Header */
/**
 ******************************************************************************
 * @file           : main.c
 * @brief          : Main program body
 ******************************************************************************
 * @attention
 *
 * Copyright (c) 2025 STMicroelectronics.
 * All rights reserved.
 *
 * This software is licensed under terms that can be found in the LICENSE file
 * in the root directory of this software component.
 * If no LICENSE file comes with this software, it is provided AS-IS.
 *
 ******************************************************************************
 */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <string.h>
#include "cmox_crypto.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define CHUNK_SIZE  48u   /* Chunk size (in bytes) when data to hash are processed by chunk */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

/* USER CODE BEGIN PV */
cmox_sha256_handle_t sha256_ctx;

__IO TestStatus glob_status = FAILED;

/** Extract from SHA256LongMsg.rsp
 *
 Len = 100
 Msg = "Hello world! Let's create something amazing together. The journey begins with a single line of code."
 MD = e507707ba5aef6e7c76786a87095f8196d643aeb8a6ad468b4c2b558a3f4ca80

 */
const uint8_t Message[] =
		"Hello world! Let's create something amazing together. The journey begins with a single line of code.";
const uint8_t Expected_Hash[] = { 0Xe5, 0X07, 0X70, 0X7b, 0Xa5, 0Xae, 0Xf6,
		0Xe7, 0Xc7, 0X67, 0X86, 0Xa8, 0X70, 0X95, 0Xf8, 0X19, 0X6d, 0X64, 0X3a,
		0Xeb, 0X8a, 0X6a, 0Xd4, 0X68, 0Xb4, 0Xc2, 0Xb5, 0X58, 0Xa3, 0Xf4, 0Xca,
		0X80 };

/* Computed data buffer */
uint8_t computed_hash[CMOX_SHA256_SIZE];

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */
	cmox_hash_retval_t retval;
	size_t computed_size;
	/* General hash context */
	cmox_hash_handle_t *hash_ctx;
	/* Index for piecemeal processing */
	uint32_t index;

	/* STM32G4xx HAL library initialization:
	 - Configure the Flash prefetch
	 - Systick timer is configured by default as source of time base, but user
	 can eventually implement his proper time base source (a general purpose
	 timer for example or other time source), keeping in mind that Time base
	 duration should be kept 1ms since PPP_TIMEOUT_VALUEs are defined and
	 handled in milliseconds basis.
	 - Set NVIC Group Priority to 4
	 - Low Level Initialization
	 */
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */
	cmox_init_arg_t init_target = { CMOX_INIT_TARGET_AUTO, NULL };
  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  /* USER CODE BEGIN 2 */
	/* Initialize cryptographic library */
	if (cmox_initialize(&init_target) != CMOX_INIT_SUCCESS) {
		Error_Handler();
	}

	/* --------------------------------------------------------------------------
	 * SINGLE CALL USAGE
	 * --------------------------------------------------------------------------
	 */
	/* Compute directly the digest passing all the needed parameters */
	retval = cmox_hash_compute(CMOX_SHA256_ALGO, /* Use SHA256 algorithm */
	Message, (sizeof(Message) - 1), /* Message to digest */
	computed_hash, /* Data buffer to receive digest data */
	CMOX_SHA256_SIZE, /* Expected digest size */
	&computed_size); /* Size of computed digest */

	/* Verify API returned value */
	if (retval != CMOX_HASH_SUCCESS) {
		Error_Handler();
	}

	/* Verify generated data size is the expected one */
	if (computed_size != CMOX_SHA256_SIZE) {
		Error_Handler();
	}

	/* Verify generated data are the expected ones */
	if (memcmp(Expected_Hash, computed_hash, computed_size) != 0) {
		Error_Handler();
	}

	/* --------------------------------------------------------------------------
	 * MULTIPLE CALLS USAGE
	 * --------------------------------------------------------------------------
	 */

	/* Construct a hash context that is configured to perform SHA256 digest operations */
	hash_ctx = cmox_sha256_construct(&sha256_ctx);
	if (hash_ctx == NULL) {
		Error_Handler();
	}

	/* Initialize the hash context */
	retval = cmox_hash_init(hash_ctx);
	if (retval != CMOX_HASH_SUCCESS) {
		Error_Handler();
	}

	/* Set the desired size for the digest to compute: note that in the case
	 where the size of the digest is the default for the algorithm, it is
	 possible to skip this call. */
	retval = cmox_hash_setTagLen(hash_ctx, CMOX_SHA256_SIZE);
	if (retval != CMOX_HASH_SUCCESS) {
		Error_Handler();
	}

	/* Append the message to be hashed by chunks of CHUNK_SIZE Bytes */
	for (index = 0; index < (sizeof(Message) - CHUNK_SIZE); index += CHUNK_SIZE)
	{
		retval = cmox_hash_append(hash_ctx, &Message[index], CHUNK_SIZE); /* Chunk of data to digest */

		/* Verify API returned value */
		if (retval != CMOX_HASH_SUCCESS) {
			Error_Handler();
		}
	}
	/* Append the last part of the message if needed */
	if (index < sizeof(Message)) {
		retval = cmox_hash_append(hash_ctx, &Message[index],
				sizeof(Message) - index); /* Last part of data to digest */

		/* Verify API returned value */
		if (retval != CMOX_HASH_SUCCESS) {
			Error_Handler();
		}
	}

	/* Generate the digest data */
	retval = cmox_hash_generateTag(hash_ctx, computed_hash, &computed_size);

	/* Verify API returned value */
	if (retval != CMOX_HASH_SUCCESS) {
		Error_Handler();
	}

	/* Verify generated data size is the expected one */
	if (computed_size != CMOX_SHA256_SIZE) {
		Error_Handler();
	}

	/* Verify generated data are the expected ones */
	if (memcmp(Expected_Hash, computed_hash, computed_size) != 0) {
		Error_Handler();
	}

	/* Cleanup the context */
	retval = cmox_hash_cleanup(hash_ctx);
	if (retval != CMOX_HASH_SUCCESS) {
		Error_Handler();
	}

	/* No more need of cryptographic services, finalize cryptographic library */
	if (cmox_finalize(NULL) != CMOX_INIT_SUCCESS) {
		Error_Handler();
	}

	/* Turn on LED2 in an infinite loop in case of AES CBC operations are successful */
	HAL_GPIO_WritePin(BLUE_LED_GPIO_Port, BLUE_LED_Pin, GPIO_PIN_SET);
	glob_status = PASSED;
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
	while (1) {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
	}
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1_BOOST);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = RCC_PLLM_DIV2;
  RCC_OscInitStruct.PLL.PLLN = 85;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOF_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(BLUE_LED_GPIO_Port, BLUE_LED_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : BLUE_LED_Pin */
  GPIO_InitStruct.Pin = BLUE_LED_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_PULLDOWN;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(BLUE_LED_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
	/* User can add his own implementation to report the HAL error return state */
	__disable_irq();
	while (1) {
		HAL_GPIO_TogglePin(BLUE_LED_GPIO_Port, BLUE_LED_Pin);
		HAL_Delay(250);
	}
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
