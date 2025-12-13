/*
 * FloofOS - Fast Line-rate Offload On Fabric Operating System
 * Copyright (C) 2025 FloofOS Networks <dev@floofos.io>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License.
 */

package readline

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

type HelpHandler func(line string)
type CompleteHandler func(line string) []string

type Readline struct {
	history      []string
	historyIndex int
	prompt       string
	onHelp       HelpHandler
	onComplete   CompleteHandler
	termState    *term.State
	fd           int
}

func New() *Readline {
	return &Readline{
		history:      make([]string, 0),
		historyIndex: -1,
		fd:           int(os.Stdin.Fd()),
	}
}

func (r *Readline) SetPrompt(prompt string) {
	r.prompt = prompt
}

func (r *Readline) SetHelpHandler(handler HelpHandler) {
	r.onHelp = handler
}

func (r *Readline) SetCompleteHandler(handler CompleteHandler) {
	r.onComplete = handler
}

func (r *Readline) AddHistory(line string) {
	if line != "" && (len(r.history) == 0 || r.history[len(r.history)-1] != line) {
		r.history = append(r.history, line)
	}
	r.historyIndex = len(r.history)
}

func (r *Readline) Readline() (string, error) {
	if !term.IsTerminal(r.fd) {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}

	oldState, err := term.MakeRaw(r.fd)
	if err != nil {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	r.termState = oldState
	defer term.Restore(r.fd, oldState)

	fmt.Print(r.prompt)

	var line []byte
	var pos int
	r.historyIndex = len(r.history)
	tempLine := ""

	buf := make([]byte, 4)

	for {
		n, err := os.Stdin.Read(buf[:1])
		if err != nil || n == 0 {
			fmt.Print("\r\n")
			return string(line), err
		}

		char := buf[0]

		switch char {
		case '?':
			fmt.Print("?")
			fmt.Print("\r\n")

			term.Restore(r.fd, oldState)

			if r.onHelp != nil {
				currentLine := string(line)
				r.onHelp(currentLine)
			}

			term.MakeRaw(r.fd)

			fmt.Print(r.prompt)
			fmt.Print(string(line))
			pos = len(line)

		case 13, 10:
			fmt.Print("\r\n")
			result := string(line)
			r.AddHistory(result)
			return result, nil

		case 127, 8:
			if pos > 0 {
				copy(line[pos-1:], line[pos:])
				line = line[:len(line)-1]
				pos--
				r.redrawLine(line, pos)
			}

		case 3:
			fmt.Print("^C\r\n")
			return "", nil

		case 4:
			if len(line) == 0 {
				fmt.Print("\r\n")
				return "", fmt.Errorf("EOF")
			}

		case 9:
			if r.onComplete != nil {
				currentLine := string(line)
				completions := r.onComplete(currentLine)

				if len(completions) == 0 {
					continue
				}

				if len(completions) == 1 {
					completion := completions[0]
					words := strings.Fields(currentLine)

					if len(words) == 0 {
						line = []byte(completion + " ")
						pos = len(line)
						r.redrawLine(line, pos)
					} else {
						lastWord := words[len(words)-1]
						endsWithSpace := len(currentLine) > 0 && currentLine[len(currentLine)-1] == ' '

						if endsWithSpace {
							line = append(line, []byte(completion+" ")...)
							pos = len(line)
							r.redrawLine(line, pos)
						} else if strings.HasPrefix(strings.ToLower(completion), strings.ToLower(lastWord)) {
							toAdd := completion[len(lastWord):]
							line = append(line, []byte(toAdd+" ")...)
							pos = len(line)
							r.redrawLine(line, pos)
						} else {
							line = append(line, []byte(" "+completion+" ")...)
							pos = len(line)
							r.redrawLine(line, pos)
						}
					}
				} else {
					fmt.Print("\r\n")
					for _, c := range completions {
						fmt.Print("  " + c + "\r\n")
					}
					fmt.Print(r.prompt)
					fmt.Print(string(line))
					pos = len(line)

					commonPrefix := findCommonPrefix(completions)
					if commonPrefix != "" {
						words := strings.Fields(currentLine)
						if len(words) > 0 {
							lastWord := words[len(words)-1]
							endsWithSpace := len(currentLine) > 0 && currentLine[len(currentLine)-1] == ' '
							if !endsWithSpace && strings.HasPrefix(strings.ToLower(commonPrefix), strings.ToLower(lastWord)) && len(commonPrefix) > len(lastWord) {
								toAdd := commonPrefix[len(lastWord):]
								line = append(line, []byte(toAdd)...)
								pos = len(line)
								r.redrawLine(line, pos)
							}
						}
					}
				}
			}

		case 27:
			n, _ := os.Stdin.Read(buf[1:3])
			if n >= 2 && buf[1] == '[' {
				switch buf[2] {
				case 'A':
					if r.historyIndex > 0 {
						if r.historyIndex == len(r.history) {
							tempLine = string(line)
						}
						r.historyIndex--
						line = []byte(r.history[r.historyIndex])
						pos = len(line)
						r.redrawLine(line, pos)
					}
				case 'B':
					if r.historyIndex < len(r.history) {
						r.historyIndex++
						if r.historyIndex == len(r.history) {
							line = []byte(tempLine)
						} else {
							line = []byte(r.history[r.historyIndex])
						}
						pos = len(line)
						r.redrawLine(line, pos)
					}
				case 'C':
					if pos < len(line) {
						pos++
						fmt.Print("\033[C")
					}
				case 'D':
					if pos > 0 {
						pos--
						fmt.Print("\033[D")
					}
				case 'H':
					if pos > 0 {
						fmt.Printf("\033[%dD", pos)
						pos = 0
					}
				case 'F':
					if pos < len(line) {
						fmt.Printf("\033[%dC", len(line)-pos)
						pos = len(line)
					}
				case '3':
					os.Stdin.Read(buf[:1])
					if pos < len(line) {
						copy(line[pos:], line[pos+1:])
						line = line[:len(line)-1]
						r.redrawLine(line, pos)
					}
				}
			}

		default:
			if char >= 32 && char < 127 {
				if pos == len(line) {
					line = append(line, char)
					pos++
					fmt.Print(string(char))
				} else {
					newLine := make([]byte, len(line)+1)
					copy(newLine, line[:pos])
					newLine[pos] = char
					copy(newLine[pos+1:], line[pos:])
					line = newLine
					pos++
					r.redrawLine(line, pos)
				}
			}
		}
	}
}

func (r *Readline) redrawLine(line []byte, pos int) {
	fmt.Print("\r\033[K")
	fmt.Print(r.prompt)
	fmt.Print(string(line))
	if pos < len(line) {
		fmt.Printf("\033[%dD", len(line)-pos)
	}
}

func (r *Readline) Close() {
	if r.termState != nil {
		term.Restore(r.fd, r.termState)
	}
}

func findCommonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	prefix := strs[0]
	for _, s := range strs[1:] {
		for len(prefix) > 0 && !strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix)) {
			prefix = prefix[:len(prefix)-1]
		}
	}
	return prefix
}
