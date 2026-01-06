package configs

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	loggerPkg "github.com/SmartFPGATutor/seulogin/pkg/logger"
	"go.uber.org/zap"
)

//go:embed config_example.toml
var defaultConfigFile embed.FS

var logger = loggerPkg.GetLogger()

type Config struct {
	CronExp        *string          `json:"cron_exp" toml:"cron_exp"`
	RetryInterval  *int             `json:"retry_interval" toml:"retry_interval"`
	RetryTimes     *int             `json:"retry_times" toml:"retry_times"`
	LogFile        *string          `json:"log_file" toml:"log_file"`
	LogLevel       *string          `json:"log_level" toml:"log_level"`
	LoginIP        []LoginIP        `json:"login_ip" toml:"login_ip"`
	LoginInterface []LoginInterface `json:"login_interface" toml:"login_interface"`
	LoginUPnP      []LoginUPnP      `json:"login_upnp" toml:"login_upnp"`
}

type LoginIP struct {
	IP       *string `json:"ip" toml:"ip"`
	Username *string `json:"username" toml:"username"`
	Password *string `json:"password" toml:"password"`
	UseIP    *bool   `json:"use_ip" toml:"use_ip"`
}

type LoginInterface struct {
	Interface *string `json:"interface" toml:"interface"`
	Username  *string `json:"username" toml:"username"`
	Password  *string `json:"password" toml:"password"`
	UseIP     *bool   `json:"use_ip" toml:"use_ip"`
}

type LoginUPnP struct {
	Interface *string  `json:"interface" toml:"interface"`
	Username  *string  `json:"username" toml:"username"`
	Password  *string  `json:"password" toml:"password"`
	UseIP     *bool    `json:"use_ip" toml:"use_ip"`
	Exclude   []string `json:"exclude" toml:"exclude"`
}

func DetectConfigType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	return ext
}

func LoadConfig(path string) (*Config, error) {
	logger.Debug("Loading config", zap.String("path", path))
	var config Config

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".toml":
		_, err := toml.DecodeFile(path, &config)
		if err != nil {
			return nil, err
		}
	case ".json":
		file, err := os.ReadFile(path)
		if err != nil {
			logger.Error("Failed to read file", zap.String("path", path), zap.Error(err))
			return nil, err
		}
		if err := json.Unmarshal(file, &config); err != nil {
			logger.Error("Failed to unmarshal json", zap.String("path", path), zap.Error(err))
			return nil, err
		}
	default:
		logger.Error("Unsupported file extension", zap.String("path", path), zap.String("extension", ext))
		return nil, fmt.Errorf("unsupported file extension: %s", ext)
	}

	if config.LogFile != nil && *config.LogFile != "" {
		logger.SetLogFilePath(*config.LogFile)
		logger.SetVerbose(logger.GetVerbose())
		logger.SetSaveToFile(true)
	}
	logger.Reset()

	return &config, nil
}

func PrettyPrintConfig(config *Config) {
	logger.Debug("PrettyPrintConfig")
	if config.LogLevel != nil {
		fmt.Printf("日志级别: %s\n", *config.LogLevel)
	} else {
		fmt.Println("没有配置日志级别, 使用默认级别 info")
	}
	if len(config.LoginIP) > 0 {
		for _, loginIP := range config.LoginIP {
			fmt.Printf("\n登录 IP:\n")
			if loginIP.IP != nil {
				fmt.Printf("  IP: %s\n", *loginIP.IP)
			}
			if loginIP.Username != nil {
				fmt.Printf("  用户名: %s\n", *loginIP.Username)
			}
			if loginIP.Password != nil {
				fmt.Printf("  密码: %s\n", *loginIP.Password)
			}
			if loginIP.UseIP != nil {
				fmt.Printf("  使用 IP: %v\n", *loginIP.UseIP)
			}
		}
	} else {
		fmt.Println("没有配置登录 IP")
	}

	if len(config.LoginInterface) > 0 {
		for _, loginInterface := range config.LoginInterface {
			fmt.Printf("\n登录接口:\n")
			if loginInterface.Interface != nil {
				fmt.Printf("  接口: %s\n", *loginInterface.Interface)
			}
			if loginInterface.Username != nil {
				fmt.Printf("  用户名: %s\n", *loginInterface.Username)
			}
			if loginInterface.Password != nil {
				fmt.Printf("  密码: %s\n", *loginInterface.Password)
			}
			if loginInterface.UseIP != nil {
				fmt.Printf("  使用 IP: %v\n", *loginInterface.UseIP)
			}
		}
	} else {
		fmt.Println("没有配置登录接口")
	}

	if len(config.LoginUPnP) > 0 {
		for _, loginUPnP := range config.LoginUPnP {
			fmt.Printf("\n登录 UPnP:\n")
			if loginUPnP.Interface != nil {
				fmt.Printf("  接口: %s\n", *loginUPnP.Interface)
			}
			if loginUPnP.Username != nil {
				fmt.Printf("  用户名: %s\n", *loginUPnP.Username)
			}
			if loginUPnP.Password != nil {
				fmt.Printf("  密码: %s\n", *loginUPnP.Password)
			}
			if loginUPnP.UseIP != nil {
				fmt.Printf("  使用 IP: %v\n", *loginUPnP.UseIP)
			}
		}
	} else {
		fmt.Println("没有配置登录 UPnP")
	}
}

func GenDefaultConfigToml(outputPath string) error {
	logger.Debug("Generating default config toml")
	if outputPath == "" {
		outputPath = "./config_example.toml"
	}

	if !strings.HasSuffix(outputPath, ".toml") {
		logger.Error("Output path must have a .toml extension", zap.String("Given Path", outputPath))
		return fmt.Errorf("output path must have a .toml extension: %s", outputPath)
	}

	// copy embeded file to savePath
	file, err := defaultConfigFile.ReadFile("config_example.toml")
	if err != nil {
		logger.Error("Failed to read default config file", zap.Error(err))
		return fmt.Errorf("failed to read default config file: %w", err)
	}

	err = os.WriteFile(outputPath, file, 0o644)
	if err != nil {
		logger.Error("Failed to write default config file", zap.Error(err))
		return fmt.Errorf("failed to write default config file: %w", err)
	}
	return nil
}

func GenDefaultConfigJson(outputPath string) error {
	logger.Debug("Generating default config json")
	if outputPath == "" {
		outputPath = "./config_example.json"
	}

	if !strings.HasSuffix(outputPath, ".json") {
		logger.Error("Output path must have a .json extension", zap.String("Given Path", outputPath))
		return fmt.Errorf("output path must have a .json extension: %s", outputPath)
	}

	var defaultConfig Config
	_, err := toml.DecodeFS(defaultConfigFile, "config_example.toml", &defaultConfig)
	if err != nil {
		logger.Error("Failed to decode default config file", zap.Error(err))
		return fmt.Errorf("failed to decode default config file: %w", err)
	}

	jsonData, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal default config file", zap.Error(err))
		return fmt.Errorf("failed to marshal default config file: %w", err)
	}

	err = os.WriteFile(outputPath, jsonData, 0o644)
	if err != nil {
		logger.Error("Failed to write default config file", zap.Error(err))
		return fmt.Errorf("failed to write default config file: %w", err)
	}
	return nil
}

func CheckConfig(path string) error {
	logger.Debug("Checking config", zap.String("path", path))
	config, err := LoadConfig(path)
	if err != nil {
		logger.Error("Failed to load config", zap.Error(err))
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Must have at least one of the following: LoginIP, LoginInterface, LoginUPnP
	if len(config.LoginIP) == 0 && len(config.LoginInterface) == 0 && len(config.LoginUPnP) == 0 {
		logger.Error("Config must have at least one of the following: LoginIP, LoginInterface, LoginUPnP")
		return fmt.Errorf("config must have at least one of the following: LoginIP, LoginInterface, LoginUPnP")
	}

	// Every method shold have username and password
	for _, loginIP := range config.LoginIP {
		if loginIP.Username == nil || loginIP.Password == nil {
			logger.Error("LoginIP must have username and password", zap.String("LoginIP", *loginIP.IP))
			return fmt.Errorf("LoginIP must have username and password: %v", loginIP.IP)
		}
	}
	for _, loginInterface := range config.LoginInterface {
		if loginInterface.Username == nil || loginInterface.Password == nil {
			logger.Error("LoginInterface must have username and password", zap.String("LoginInterface", *loginInterface.Interface))
			return fmt.Errorf("LoginInterface must have username and password: %v", loginInterface.Interface)
		}
	}
	for _, loginUPnP := range config.LoginUPnP {
		if loginUPnP.Username == nil || loginUPnP.Password == nil {
			logger.Error("LoginUPnP must have username and password", zap.String("LoginUPnP", *loginUPnP.Interface))
			return fmt.Errorf("LoginUPnP must have username and password: %v", loginUPnP.Interface)
		}
	}

	logger.Info("Config Check Success")
	// PrettyPrintConfig(config)
	return nil
}

func SaveConfigToToml(config *Config, path string) error {
	logger.Debug("Saving config to toml", zap.String("path", path))
	if path == "" {
		path = "./config.toml"
	}

	if !strings.HasSuffix(path, ".toml") {
		logger.Error("Output path must have a .toml extension", zap.String("Given Path", path))
		return fmt.Errorf("output path must have a .toml extension: %s", path)
	}

	file, err := os.Create(path)
	if err != nil {
		logger.Error("Failed to create config file", zap.Error(err))
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	encoder := toml.NewEncoder(file)
	err = encoder.Encode(config)
	if err != nil {
		logger.Error("Failed to encode config file", zap.Error(err))
		return fmt.Errorf("failed to encode config file: %w", err)
	}

	logger.Info("Config saved to toml", zap.String("path", path))
	return nil
}

func SaveConfigToJson(config *Config, path string) error {
	logger.Debug("Saving config to json", zap.String("path", path))
	if path == "" {
		path = "./config.json"
	}

	if !strings.HasSuffix(path, ".json") {
		logger.Error("Output path must have a .json extension", zap.String("Given Path", path))
		return fmt.Errorf("output path must have a .json extension: %s", path)
	}

	jsonData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal config file", zap.Error(err))
		return fmt.Errorf("failed to marshal config file: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		logger.Error("Failed to create config file", zap.Error(err))
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(jsonData)
	if err != nil {
		logger.Error("Failed to write config file", zap.Error(err))
		return fmt.Errorf("failed to write config file: %w", err)
	}

	logger.Info("Config saved to json", zap.String("path", path))
	return nil
}

func ConvertConfig(inputPath, outputPath string) error {
	logger.Debug("Converting config", zap.String("inputPath", inputPath), zap.String("outputPath", outputPath))

	if inputPath == outputPath {
		logger.Error("Input path and output path are the same", zap.String("inputPath", inputPath), zap.String("outputPath", outputPath))
		return fmt.Errorf("input path and output path are the same: %s", inputPath)
	}

	extInput := strings.ToLower(filepath.Ext(inputPath))
	extOutput := strings.ToLower(filepath.Ext(outputPath))

	if extInput != ".toml" && extInput != ".json" {
		logger.Error("Input path must have a .toml or .json extension", zap.String("Given Path", inputPath))
		return fmt.Errorf("input path must have a .toml or .json extension: %s", inputPath)
	}

	if extOutput != ".toml" && extOutput != ".json" {
		logger.Error("Output path must have a .toml or .json extension", zap.String("Given Path", outputPath))
		return fmt.Errorf("output path must have a .toml or .json extension: %s", outputPath)
	}

	config, err := LoadConfig(inputPath)
	if err != nil {
		logger.Error("Failed to load config", zap.Error(err))
		return fmt.Errorf("failed to load config: %w", err)
	}

	switch extOutput {
	case ".toml":
		return SaveConfigToToml(config, outputPath)
	case ".json":
		return SaveConfigToJson(config, outputPath)
	}

	logger.Info("Config converted", zap.String("inputPath", inputPath), zap.String("outputPath", outputPath))
	return nil
}
