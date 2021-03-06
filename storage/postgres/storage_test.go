/*
 * Copyright 2018 The Service Manager Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package postgres

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Postgres Storage", func() {
	pgStorage := &postgresStorage{}

	Describe("Broker", func() {
		Context("Called with uninitialized db", func() {
			It("Should panic", func() {
				Expect(func() { pgStorage.Broker() }).To(Panic())
			})
		})
	})

	Describe("Platform", func() {
		Context("Called with uninitialized db", func() {
			It("Should panic", func() {
				Expect(func() { pgStorage.Platform() }).To(Panic())
			})
		})
	})

	Describe("Credentials", func() {
		Context("Called with uninitialized db", func() {
			It("Should panic", func() {
				Expect(func() { pgStorage.Credentials() }).To(Panic())
			})
		})
	})

	Context("Security Storage", func() {
		Context("Called with uninitialized db", func() {
			It("Should panic", func() {
				Expect(func() {pgStorage.Security()})
			})
		})
	})

	Describe("Ping", func() {
		Context("Called with uninitialized db", func() {
			It("Should panic", func() {
				Expect(func() { pgStorage.Ping() }).To(Panic())
			})
		})
	})

	Describe("Open", func() {
		Context("Called with empty uri", func() {
			It("Should return error", func() {
				err := pgStorage.Open("", nil)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("storage URI cannot be empty"))
			})
		})

		Context("Called with invalid postgres uri", func() {
			It("Should panic", func() {
				Expect(func() { pgStorage.Open("invalid_uri", nil) }).To(Panic())
			})
		})
	})

})
